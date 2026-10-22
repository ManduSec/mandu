/**
 * sse-reserve-expand — expand a `$MDU:` token into an N-row reserve block on
 * the model→agent Responses SSE stream (Codex), so the agent's TUI lays out
 * one row per row of the secret value and the reply filter can paint row i
 * into reserved row i.
 *
 * Mandu Track A (interceptors/openai-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §3.2 (v1 eligibility), §3.5 (the
 * transformer), §5 (security), §11.3-§11.5 (v2: wrapped rows, tokens inside a
 * line), §11.7 (Codex). PROVENANCE: NEW Mandu code (2026-09-30), the
 * Responses twin of interceptors/anthropic-proxy/src/sse-reserve-expand.ts
 * (the Messages expander): the same grammar (reserve-block.ts), the same
 * eligibility (reserve-context.ts decideReserve), the same hold and release
 * discipline, and the Responses repacker's framing rule (text-repack.ts).
 *
 * THE ONE RESPONSE-SIDE CHANGE OF TEXT. Every other response transformer
 * keeps the text byte-identical. This one appends a head suffix `/1:N` (v1)
 * or `/1:N:W:F` (v2) and N−1 continuation rows to a token T. No original
 * moves: the proxy learns only N, from the arbiter's `symbolShape` (human
 * plane), and the next request collapses the block back to T before the
 * model sees it (reserve-request.ts). The proxy's ResponseSniffer taps the
 * raw upstream chunks, so the tllm_call records the model's own text.
 *
 * EVENTS ARE NEVER INVENTED OR DROPPED (the Responses repacker's rule: an SDK
 * may track `sequence_number`). Text only moves FORWARD between consecutive
 * `response.output_text.delta` events of the same output item + content part,
 * and a delta's text may grow by a block. Per part:
 *   - a delta whose text (with the carry from before it) ends in a possible
 *     in-flight token (text-repack.ts danglingTokenStart) is HELD whole, since
 *     the token's following character decides it;
 *   - the next delta of the same part: its first char decides the held
 *     token, and the held event goes out with all its text. Only when a
 *     token runs across the two deltas (never after the repacker) does the
 *     held event go out with the text before it, the token's start carried
 *     into the next delta;
 *   - the part's `response.output_text.done` (or `content_part.done`): the
 *     line ends right after the held token (the char is ""), so the held
 *     event goes out with ALL its text, the token decided;
 *   - anything else (another part's text, any other event, the stream end):
 *     the held event goes out with all its text, a token ending it left as
 *     is (never guessed).
 * Each token is decided by reserve-context.ts decideReserve: v2 heads when
 * the relay paints them (`wrap` and `cols`), a token alone on its line or
 * inside a line; v1 heads (alone on its line only) otherwise. The mode is
 * fixed per stream the first time a text may hold a token.
 *
 * EVERY SNAPSHOT AGREES. The part's final text also rides in
 * `response.output_text.done` (`text`), `response.content_part.done`
 * (`part.text`), `response.output_item.done` (the message item's output_text
 * content) and `response.completed` (`response.output[…]`), and Codex keeps
 * the assembled item as its history. So, as the tool-call rewriter keeps
 * its four payload-bearing events consistent (sse-rewrite.ts), each of these
 * gets the SAME expanded text: a snapshot whose text equals the model's text
 * of that part, as the deltas carried it, is replaced by the text the deltas
 * went out with. A snapshot that does not match is left alone (no rewrite,
 * never guess).
 *
 * FAIL-SAFE: "no rewrite, never guess". `lines`, `layout` and `shape` are the
 * proxy's eligibility callbacks (reserve-eligibility.ts: relay mode, kill
 * switch, symbolShape under a deadline); a null, a throw or a non-integer
 * means the token passes through unchanged. A part whose deltas carry
 * `logprobs` (which index the original text) is never changed. An event this
 * cannot parse passes through verbatim; an event it does not change relays
 * byte-verbatim.
 */

import { danglingTokenStart } from "./text-repack.js";
import {
  canonicalToken,
  findTokens,
  reserveBlock,
  reserveHeadSuffix,
  reserveRows,
  tokenHash,
  validLayout,
  type ReserveLayout,
} from "./reserve-block.js";
import { advanceContext, decideReserve, newLineContext, suffixBreak, type LineContext, type ReserveDecision } from "./reserve-context.js";
import { layoutWidth } from "./reserve-layout.js";
import type { ReserveShape } from "./reserve-eligibility.js";

/** One expansion, for the `reserve_expand` event. */
export interface ReserveExpansion {
  /** The output item's `output_index` (-1 when absent). */
  index: number;
  /** The token as written. */
  token: string;
  hash: string;
  /** N, the rows reserved. */
  rows: number;
  /** v2 only: the head's W and F. */
  width?: number;
  first?: number;
}

export interface ReserveExpandOptions {
  /** The value's line count for a token (canonical spelling), or null to
   *  leave it (v1 heads). Should be bounded in time; a rejection counts as
   *  null. */
  lines: (token: string) => Promise<number | null>;
  /** v2: the relay's terminal columns when it paints v2 heads, else null,
   *  and where the TUI counts a TAB's stops from (§19.7; absent: `screen`,
   *  Codex's). Absent (or `shape` absent): v1 only. */
  layout?: () => Promise<{ cols: number; tabs?: "content" } | null>;
  /** v2: the value's shape at content width `width`, head row `first`, its
   *  TAB stops counted from column `indent` (§11.2: `cols − width`, the
   *  content area's terminal column, or 0 for a TUI that counts from the
   *  content area, §19.7). */
  shape?: (token: string, width: number, first: number, indent?: number) => Promise<ReserveShape | null>;
  /** Row cap (reserve-block.ts parseReserveMax). */
  cap: number;
  /** v2: expand a token that is a whole code span, in the span form
   *  (reserve-context.ts DecideInput.codeSpan, §12). The Codex proxy leaves
   *  it off: Codex's renderer was not probed for it. */
  codeSpan?: boolean;
  /** Called once per expanded token (best-effort observability). */
  onExpand?: (e: ReserveExpansion) => void;
  /** Record the block with the arbiter before it is sent (§3.8), `token`
   *  canonical, so the reply filter can lay out a continuation row whose
   *  head never reaches the screen. Should be bounded in time; a rejection
   *  is ignored (the block still goes out). */
  register?: (e: ReserveExpansion) => Promise<void>;
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** One output_text content part. */
interface PartState {
  /** Where the next released char lands (the model's raw text). */
  ctx: LineContext;
  /** The model's text of the part released so far. */
  model: string;
  /** The text the agent got for it so far. */
  out: string;
  /** A delta carried logprobs: never change this part. */
  frozen: boolean;
}

/** The held delta event. */
interface Held {
  raw: string;
  obj: Json;
  key: string;
  /** The event's text with the carry from before it. */
  full: string;
  /** Whether `full` differs from the event's own text. */
  carried: boolean;
}

/** A possible token anywhere in a text. */
const TOKEN_HINT_RE = /\$MDU:/;

/**
 * The hold (§14): from the first token on the text's unfinished last line,
 * or a token that may still be arriving at its end, whichever is first. So
 * a token is decided with its whole line known, and the rest of that line
 * rides into the next delta until the line ends. The Messages expander's
 * rule (anthropic-proxy sse-reserve-expand.ts lineHoldStart).
 */
function lineHoldStart(full: string): number {
  const k = danglingTokenStart(full);
  const ls = full.lastIndexOf("\n") + 1;
  const toks = findTokens(full.slice(ls));
  return toks.length > 0 ? Math.min(k, ls + toks[0]!.start) : k;
}

const DELTA = "response.output_text.delta";
const TEXT_DONE = "response.output_text.done";
const PART_ADDED = "response.content_part.added";
const PART_DONE = "response.content_part.done";
const ITEM_DONE = "response.output_item.done";

/** The part key: the item id (the same in every snapshot), else the output
 *  index, plus the content index. */
function partKey(itemId: unknown, outputIndex: unknown, contentIndex: unknown): string {
  const item = typeof itemId === "string" && itemId !== "" ? itemId : `#${String(outputIndex ?? "")}`;
  return `${item}\u0000${String(contentIndex ?? "")}`;
}

function hasLogprobs(obj: Json): boolean {
  const lp = obj["logprobs"];
  return Array.isArray(lp) ? lp.length > 0 : lp != null;
}

export class ResponsesReserveExpander {
  private readonly framer = new SseFramer();
  private readonly parts = new Map<string, PartState>();
  private held: Held | null = null;
  private out: string[] = [];
  /** Fixed at the first text that may hold a token. */
  private mode: "unknown" | "v1" | "v2" = "unknown";
  /** v2: the relay's columns; null = v1 heads. */
  private cols: number | null = null;
  /** v2: the TUI counts a TAB's stops from the content area (§19.7), fixed
   *  with the mode. */
  private contentTabs = false;

  constructor(private readonly opts: ReserveExpandOptions) {}

  /** Feed a raw SSE chunk; resolves to the bytes to relay now. Never rejects. */
  async feed(chunk: string): Promise<string> {
    for (const raw of this.framer.push(chunk)) await this.handle(raw);
    return this.drain();
  }

  /** At stream end: the held event with all its text (a token ending it not
   *  expanded), then any partial frame verbatim. Bytes are never swallowed. */
  async end(): Promise<string> {
    await this.release("other");
    const rest = this.framer.rest();
    if (rest !== "") this.out.push(rest);
    return this.drain();
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private async handle(raw: string): Promise<void> {
    const data = eventData(raw);
    if (data === null) {
      this.out.push(raw); // a comment / keepalive: nothing to render, the hold stays
      return;
    }
    let obj: unknown = null;
    try { obj = JSON.parse(data); } catch { obj = null; }
    if (!isObj(obj)) {
      await this.release("other");
      this.out.push(raw);
      return;
    }
    const type = typeof obj["type"] === "string" ? (obj["type"] as string) : eventName(raw);

    if (type === DELTA && typeof obj["delta"] === "string") {
      await this.handleDelta(raw, obj);
      return;
    }

    // The part's own end proves the line ends after a held token.
    const key = partKey(obj["item_id"], obj["output_index"], obj["content_index"]);
    const endsHeld = (type === TEXT_DONE || type === PART_DONE) && this.held?.key === key;
    await this.release(endsHeld ? "end" : "other");

    if (type === PART_ADDED) {
      const part = obj["part"];
      if (isObj(part) && part["type"] === "output_text") {
        const t = typeof part["text"] === "string" ? (part["text"] as string) : "";
        const ctx = newLineContext();
        advanceContext(ctx, t);
        this.parts.set(key, { ctx, model: t, out: t, frozen: false });
      }
      this.out.push(raw);
      return;
    }
    if (type === TEXT_DONE && typeof obj["text"] === "string") {
      const text = this.snapshotText(key, obj["text"] as string);
      this.out.push(text === null ? raw : serialize(raw, { ...obj, text }));
      return;
    }
    if (type === PART_DONE && isObj(obj["part"])) {
      const part = obj["part"] as Json;
      const text = part["type"] === "output_text" && typeof part["text"] === "string"
        ? this.snapshotText(key, part["text"] as string)
        : null;
      this.out.push(text === null ? raw : serialize(raw, { ...obj, part: { ...part, text } }));
      return;
    }
    if (type === ITEM_DONE && isObj(obj["item"])) {
      const item = this.snapshotItem(obj["item"] as Json, obj["output_index"]);
      this.out.push(item === null ? raw : serialize(raw, { ...obj, item }));
      return;
    }
    // response.completed (and any other event carrying the final output[]).
    const resp = obj["response"];
    if (isObj(resp) && Array.isArray(resp["output"])) {
      let changed = false;
      const output = (resp["output"] as unknown[]).map((it, i) => {
        if (!isObj(it)) return it;
        const next = this.snapshotItem(it, i);
        if (next === null) return it;
        changed = true;
        return next;
      });
      this.out.push(changed ? serialize(raw, { ...obj, response: { ...resp, output } }) : raw);
      return;
    }
    this.out.push(raw);
  }

  private async handleDelta(raw: string, obj: Json): Promise<void> {
    const key = partKey(obj["item_id"], obj["output_index"], obj["content_index"]);
    const text = obj["delta"] as string;
    let st = this.parts.get(key);
    if (!st) {
      st = { ctx: newLineContext(), model: "", out: "", frozen: false };
      this.parts.set(key, st);
    }
    if (st.frozen || hasLogprobs(obj)) {
      // Logprobs index the original text: never re-cut or change this
      // event. A hold before it goes out whole, its token not decided.
      await this.release("other");
      st.frozen = true;
      advanceContext(st.ctx, text);
      st.model += text;
      st.out += text;
      this.out.push(raw);
      return;
    }
    let carry = "";
    if (this.held !== null && this.held.key === key) {
      carry = await this.cut(text);
    } else {
      await this.release("other");
    }
    const full = carry + text;
    if (this.mode === "unknown" && (danglingTokenStart(full) < full.length || TOKEN_HINT_RE.test(full))) {
      await this.resolveMode();
    }
    if (this.holdStart(full) < full.length) {
      this.held = { raw, obj, key, full, carried: carry !== "" };
      return;
    }
    const outText = await this.expandRegion(full, null, st, obj["output_index"]);
    st.model += full;
    st.out += outText;
    this.out.push(carry === "" && outText === text ? raw : serialize(raw, { ...obj, delta: outText }));
  }

  /** Release the held event before the next delta of its part, whose text
   *  is `next`. When no token runs across the boundary (always, after the
   *  repacker), the held event goes out with all its text, a token ending it
   *  decided by `next`'s first char, and nothing moves. Otherwise it goes
   *  out with the text before its dangling token, and the token's start is
   *  returned as the carry (prepended to the next delta). */
  private async cut(next: string): Promise<string> {
    const h = this.held!;
    const combined = h.full + next;
    // §14: a token's line is held until it ends, so the carry runs from the
    // first token on the held text's unfinished last line.
    const straddles = next === "" ||
      findTokens(combined).some((t) => t.start < h.full.length && t.end > h.full.length) ||
      danglingTokenStart(combined) < h.full.length ||
      (this.mode === "v2" && lineHoldStart(h.full) < h.full.length);
    if (!straddles) {
      this.held = null;
      const st = this.parts.get(h.key)!;
      const outText = await this.expandRegion(h.full, next[0]!, st, h.obj["output_index"]);
      st.model += h.full;
      st.out += outText;
      const own = h.obj["delta"] as string;
      this.out.push(!h.carried && outText === own ? h.raw : serialize(h.raw, { ...h.obj, delta: outText }));
      return "";
    }
    this.held = null;
    const st = this.parts.get(h.key)!;
    const k = this.holdStart(h.full);
    const region = h.full.slice(0, k);
    const outText = await this.expandRegion(region, h.full[k] ?? null, st, h.obj["output_index"]);
    st.model += region;
    st.out += outText;
    this.out.push(serialize(h.raw, { ...h.obj, delta: outText }));
    return h.full.slice(k);
  }

  /** Release the held event with all its text: `end` = the part ends right
   *  after it (a token ending it is decided with "" after it); `other` = not
   *  proven (a token ending it stays as is). */
  private async release(how: "end" | "other"): Promise<void> {
    const h = this.held;
    if (h === null) return;
    this.held = null;
    const st = this.parts.get(h.key)!;
    const outText = await this.expandRegion(h.full, how === "end" ? "" : null, st, h.obj["output_index"]);
    st.model += h.full;
    st.out += outText;
    const own = h.obj["delta"] as string;
    this.out.push(!h.carried && outText === own ? h.raw : serialize(h.raw, { ...h.obj, delta: outText }));
  }

  /** Where a text's hold starts: v2 holds a token's whole line (§14); v1
   *  only a token that may still be arriving (a v1 relay never expands
   *  inside a line, so its stream stays byte-identical). */
  private holdStart(full: string): number {
    return this.mode === "v2" ? lineHoldStart(full) : danglingTokenStart(full);
  }

  /** Fix the mode: v2 when the relay paints v2 heads, else v1. */
  private async resolveMode(): Promise<void> {
    if (this.mode !== "unknown") return;
    let cols: number | null = null;
    let contentTabs = false;
    if (this.opts.layout && this.opts.shape) {
      try {
        const l = await this.opts.layout();
        if (l && Number.isInteger(l.cols) && l.cols > 0) {
          cols = l.cols;
          contentTabs = l.tabs === "content";
        }
      } catch {
        cols = null;
      }
    }
    this.contentTabs = contentTabs;
    this.mode = cols !== null ? "v2" : "v1";
    this.cols = cols;
  }

  /**
   * Walk the tokens of one region, advancing the part's line context over
   * the model's raw text, and expand each eligible one. `next` is the char
   * right after the region ("" = the part ends there; null = unknown, so a
   * token ending the region is not expanded). In v1 mode decideReserve
   * (cols null) admits only a token alone on its line, with a v1 head.
   */
  private async expandRegion(region: string, next: string | null, st: PartState, outputIndex: unknown): Promise<string> {
    const toks = this.mode === "unknown" ? [] : findTokens(region);
    if (toks.length === 0) {
      advanceContext(st.ctx, region);
      return region;
    }
    const index = typeof outputIndex === "number" ? outputIndex : -1;
    let out = "";
    let at = 0;
    /** Where the pending §14 break goes in `region` (-1: none). */
    let breakAt = -1;
    /** The model's text [from, to), with the pending break inserted. */
    const copy = (from: number, to: number): string => {
      if (breakAt < from || breakAt >= to) return region.slice(from, to);
      const t = region.slice(from, breakAt) + "\n" + region.slice(breakAt, to);
      breakAt = -1;
      return t;
    };
    for (const t of toks) {
      const before = region.slice(at, t.start);
      advanceContext(st.ctx, before);
      out += copy(at, t.start);
      const after = t.end < region.length ? region[t.end]! : next;
      const nl = region.indexOf("\n", t.end);
      let rest: string | undefined = nl >= 0 ? region.slice(t.end, nl) : next === "" ? region.slice(t.end) : undefined;
      if (rest?.endsWith("\r")) rest = rest.slice(0, -1);
      const lineTicks = st.ctx.line.match(/`/g)?.length ?? 0;
      const d = decideReserve({
        ctx: st.ctx, token: t.token, after, cols: this.cols, cap: this.opts.cap, codeSpan: this.opts.codeSpan === true,
        ...(rest !== undefined ? { rest } : {}),
      });
      const block = d.kind === "none" ? null : await this.expandOne(t.token, d, index, rest, lineTicks);
      advanceContext(st.ctx, t.token);
      if (block !== null) {
        out += block.text;
        st.ctx.lineExpanded = true;
        if (block.brk !== undefined) breakAt = t.end + block.brk;
      } else {
        out += t.token;
      }
      at = t.end;
    }
    const rest = region.slice(at);
    advanceContext(st.ctx, rest);
    return out + copy(at, region.length);
  }

  /** The block for one decided token, or null (no expansion). `rest`, the
   *  model's text after the token to its line end (when known), and
   *  `lineTicks`, the backticks before it, place a §14 break: `brk` is its
   *  offset after the token, where the caller inserts the `\n`. */
  private async expandOne(
    token: string, d: Exclude<ReserveDecision, { kind: "none" }>, index: number, rest?: string, lineTicks = 0,
  ): Promise<{ text: string; brk?: number } | null> {
    const canonical = canonicalToken(token);
    const hash = tokenHash(token);
    if (hash === null) return null;
    if (d.kind === "v1") {
      const rows = reserveRows(await this.askLines(canonical), this.opts.cap);
      if (rows === 0) return null;
      await this.commit({ index, token, hash, rows }, canonical);
      return { text: reserveBlock(token, rows) };
    }
    if (!validLayout(d.width, d.first)) return null;
    let s: ReserveShape | null = null;
    try {
      // The content area starts `cols − W` columns in (§11.2: TAB stops).
      // (0 when the TUI counts its TAB stops from the content area, §19.7.)
      const indent = !this.contentTabs && this.cols !== null && this.cols > d.width ? this.cols - d.width : 0;
      s = (await this.opts.shape?.(canonical, d.width, d.first, indent)) ?? null;
    } catch {
      s = null;
    }
    if (!s || typeof s !== "object") return null;
    if (typeof s.rows === "number" && Number.isInteger(s.rows)) {
      if (s.rows === 1) return this.headOnly(token, hash, d, index, s, rest, lineTicks);
      const rows = reserveRows(s.rows, this.opts.cap);
      if (rows === 0) return null;
      const layout: ReserveLayout = { width: d.width, first: d.first };
      // §14: only when the last row painted is the value's (not a cap note).
      let brk: number | undefined;
      if (!d.standalone && rest && s.rows === rows && typeof s.last === "number" && Number.isInteger(s.last) && s.last >= 0) {
        brk = suffixBreak({
          suffix: rest, last: s.last, marker: layoutWidth(`$MDU/${hash}/${rows}`), width: d.width, lineTicks,
        }) ?? undefined;
        // The break field widens the head: it must still fit where F put it.
        if (brk !== undefined && d.first > 0 && layoutWidth(token) + reserveHeadSuffix(rows, layout, brk).length > d.first) brk = undefined;
      }
      await this.commit({ index, token, hash, rows, width: d.width, first: d.first }, canonical);
      return { text: reserveBlock(token, rows, layout, d.span, brk), ...(brk !== undefined ? { brk } : {}) };
    }
    // An arbiter predating v2 answers lines only: a standalone token still
    // gets a v1 head; a token inside a line is left alone.
    if (d.standalone && typeof s.lines === "number" && Number.isInteger(s.lines)) {
      const rows = reserveRows(s.lines, this.opts.cap);
      if (rows === 0) return null;
      await this.commit({ index, token, hash, rows }, canonical);
      return { text: reserveBlock(token, rows) };
    }
    return null;
  }

  /**
   * §14, a value that fits the head's row: no rows to reserve, but the text
   * after it may still be pushed past the edge by the value. Then a
   * head-only block `T/1:1:W:F:K` carries the break; otherwise the token
   * stays as it is. The value starts W − F columns into its row (F > 0: one
   * row with F = 0 is impossible, the head row would be empty).
   */
  private async headOnly(
    token: string, hash: string, d: { width: number; first: number; standalone: boolean; span: boolean },
    index: number, s: ReserveShape, rest: string | undefined, lineTicks: number,
  ): Promise<{ text: string; brk?: number } | null> {
    if (d.standalone || !rest || d.first === 0 || typeof s.last !== "number" || !Number.isInteger(s.last) || s.last < 0) return null;
    const layout: ReserveLayout = { width: d.width, first: d.first };
    const at = d.width - d.first;
    const headWide = layoutWidth(token) + reserveHeadSuffix(1, layout, 9999).length;
    if (headWide > d.first) return null;
    const brk = suffixBreak({ suffix: rest, last: at + s.last, marker: at + headWide, width: d.width, lineTicks });
    if (brk === null) return null;
    // No rows: nothing for the §3.8 registry, which records blocks with rows.
    this.notify({ index, token, hash, rows: 1, width: d.width, first: d.first });
    return { text: reserveBlock(token, 1, layout, d.span, brk), brk };
  }

  /** Register the block with the arbiter (§3.8; awaited, so it is known
   *  before any of its rows can reach a screen), then report it. Neither
   *  can stop the expansion. */
  private async commit(e: ReserveExpansion, canonical: string): Promise<void> {
    if (this.opts.register) {
      try {
        await this.opts.register({ ...e, token: canonical });
      } catch {
        /* utility only: a headless block's rows then paint blank */
      }
    }
    this.notify(e);
  }

  private async askLines(token: string): Promise<number | null> {
    try {
      const n = await this.opts.lines(token);
      return typeof n === "number" && Number.isInteger(n) ? n : null;
    } catch {
      return null;
    }
  }

  private notify(e: ReserveExpansion): void {
    if (!this.opts.onExpand) return;
    try {
      this.opts.onExpand(e);
    } catch {
      /* observability only */
    }
  }

  /** The text a snapshot of part `key` should carry: the expanded text when
   *  the part was expanded and the snapshot holds exactly the model's text
   *  the deltas carried; else null (leave the snapshot as is). */
  private snapshotText(key: string, text: string): string | null {
    const st = this.parts.get(key);
    if (!st || st.out === st.model || text !== st.model) return null;
    return st.out;
  }

  /** A message item snapshot with each expanded output_text part replaced,
   *  or null when nothing changes. */
  private snapshotItem(item: Json, outputIndex: unknown): Json | null {
    if (item["type"] !== "message" || !Array.isArray(item["content"])) return null;
    let changed = false;
    const content = (item["content"] as unknown[]).map((c, j) => {
      if (!isObj(c) || c["type"] !== "output_text" || typeof c["text"] !== "string") return c;
      const text = this.snapshotText(partKey(item["id"], outputIndex, j), c["text"] as string);
      if (text === null) return c;
      changed = true;
      return { ...c, text };
    });
    return changed ? { ...item, content } : null;
  }

  private drain(): string {
    if (this.out.length === 0) return "";
    const s = this.out.join("");
    this.out = [];
    return s;
  }
}

// ── SSE framing (mirrors text-repack.ts) ─────────────────────────────────────

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

/** The `event:` name of one SSE event ("" when absent). */
function eventName(raw: string): string {
  for (const line of raw.split(/\r?\n/)) if (line.startsWith("event:")) return line.slice(6).trim();
  return "";
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
