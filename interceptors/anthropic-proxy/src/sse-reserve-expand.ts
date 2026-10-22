/**
 * sse-reserve-expand — expand a `$MDU:` token into an N-row reserve block on
 * the model→agent SSE stream, so the agent's TUI lays out one row per row of
 * the secret value and the reply filter can paint row i into reserved row i.
 *
 * Mandu Track A (interceptors/anthropic-proxy). Design:
 * docs/design/ui/reply-row-reservation.md §3.2 (v1 eligibility), §3.5 (this
 * transformer), §5 (security), §11.3-§11.5 (v2: wrapped rows, tokens inside a
 * line). PROVENANCE: NEW Mandu code (2026-09-30); the SSE framing mirrors
 * sse-text-repack.ts, the grammar is reserve-block.ts, v2 eligibility is
 * reserve-context.ts.
 *
 * THE ONE RESPONSE-SIDE CHANGE OF TEXT. Every other response transformer
 * keeps the text byte-identical (the repacker only re-segments it). This one
 * appends a head suffix `/1:N` (v1) or `/1:N:W:F` (v2) and N−1 continuation
 * rows to a token T. No original moves: the proxy learns only N, from the
 * arbiter's `symbolShape`, and the next request collapses the block back to
 * T before the model sees it (reserve-request.ts). The sniffer
 * (SseToolUseParser, the tllm_call event) taps the stream BEFORE this
 * transformer, so what is recorded as the model's text is the model's text.
 *
 * TWO MODES, fixed per stream the first time a text holds a possible token
 * (the relay is asked then, not before):
 *   - v1 (a relay that does not report `wrap: true` with `cols`, or no
 *     `layout` callback): byte-identical to the v1 transformer. Per
 *     content-block index of a `text` block it holds the last line of the
 *     text while it could still become a standalone token, until the next
 *     char proves or disproves it:
 *       - a `\n` after it, or the block's content_block_stop: it stands
 *         alone, and it is expanded when `lines(token)` answers ≥ 2;
 *       - anything else on the line: released as is;
 *       - a non-text delta of the block, message_stop, a restarted index or
 *         the stream end: released as is (never guessed).
 *   - v2: every token, wherever it stands on its line, is decided by
 *     reserve-context.ts decideReserve once its FOLLOWING char is known. So
 *     the hold is a complete-or-dangling token at the end of the text
 *     (text-repack.ts danglingTokenStart), wherever it is on the line,
 *     released on the next text (which gives the char), content_block_stop
 *     (the line end is the char), or as is on a non-text delta,
 *     message_stop, a restarted index or the stream end. The line context
 *     (fence, list indent, the text before the token on its line) advances
 *     over the model's raw text.
 * The expanded text goes out as ONE text_delta, so the agent never lays out
 * half a block. Every other event relays verbatim, in order; a text_delta
 * this does not change relays byte-verbatim.
 *
 * FAIL-SAFE: "no rewrite, never guess". `lines`, `layout` and `shape` are the
 * proxy's eligibility callbacks (relay mode, kill switch, symbolShape under a
 * deadline); a null, a throw or a non-integer means the token passes through
 * unchanged.
 */

import { danglingTokenStart } from "./text-repack.js";
import {
  canonicalToken,
  expandText,
  findTokens,
  reserveBlock,
  reserveHeadSuffix,
  reserveRows,
  standaloneTokens,
  tokenHash,
  validLayout,
  type ReserveLayout,
  type TextEdges,
} from "./reserve-block.js";
import { advanceContext, decideReserve, newLineContext, suffixBreak, type LineContext, type ReserveDecision } from "./reserve-context.js";
import { layoutWidth, type LayoutRule } from "./reserve-layout.js";

/** One expansion, for the `reserve_expand` event. */
export interface ReserveExpansion {
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

/** A v2 shape answer: `rows` is absent from an arbiter predating v2;
 *  `last`, the width of the last row, from one predating §14. */
export interface ReserveShape {
  lines: number;
  rows?: number;
  last?: number;
}

export interface ReserveExpandOptions {
  /** The value's line count for a token (canonical spelling), or null to
   *  leave it (v1 heads). Should be bounded in time; a rejection counts as
   *  null. */
  lines: (token: string) => Promise<number | null>;
  /** v2: the relay's terminal columns when it paints v2 heads, else null,
   *  the TUI's wrap rule (§17; absent: `ink`) and where it counts a TAB's
   *  stops from (§19.7; absent: `screen`).
   *  Absent (or `shape` absent): v1 only. */
  layout?: () => Promise<{ cols: number; rule?: LayoutRule; tabs?: "content" } | null>;
  /** v2: the value's shape at content width `width`, head row `first`,
   *  under the wrap `rule` (absent: `ink`), its TAB stops counted from
   *  column `indent` (§11.2: `cols − width`, the content area's terminal
   *  column, or 0 for a TUI that counts from the content area, §19.7). */
  shape?: (token: string, width: number, first: number, rule?: LayoutRule, indent?: number) => Promise<ReserveShape | null>;
  /** Row cap (reserve-block.ts parseReserveMax). */
  cap: number;
  /** v2: expand a token that is a whole code span, in the span form
   *  (reserve-context.ts DecideInput.codeSpan, §12). */
  codeSpan?: boolean;
  /** Called once per expanded token (best-effort observability). */
  onExpand?: (e: ReserveExpansion) => void;
  /** Record the block with the arbiter before it is sent (§3.8), `token`
   *  canonical, so the reply filter can lay out a continuation row whose
   *  head never reaches the screen. Should be bounded in time; a rejection
   *  is ignored (the block still goes out). */
  register?: (e: ReserveExpansion) => Promise<void>;
}

interface BlockState {
  /** Held text: v1, the block's last line while it may be a standalone
   *  token; v2, a possible token at the end of the text. */
  held: string;
  /** v1: the next text starts at a line start. */
  lineStart: boolean;
  /** v2: where the next released char lands (tracked in both modes, since
   *  the mode is only fixed at the first possible token). */
  ctx: LineContext;
}

/**
 * v2's hold (§14): from the first token on the text's unfinished last line,
 * or a token that may still be arriving at its end, whichever is first. So
 * a token is decided with its whole line known, and the rest of that line
 * waits for the line to end (a line of text, at most, is delayed).
 */
function lineHoldStart(full: string): number {
  const k = danglingTokenStart(full);
  const ls = full.lastIndexOf("\n") + 1;
  const toks = findTokens(full.slice(ls));
  return toks.length > 0 ? Math.min(k, ls + toks[0]!.start) : k;
}

/** A possible token anywhere in a text. */
const TOKEN_HINT_RE = /\$MDU:/;

export class SseReserveExpander {
  private buf = "";
  /** Per content-block index, for `text` blocks only. */
  private readonly blocks = new Map<number, BlockState>();
  private out: string[] = [];
  /** Fixed at the first text that may hold a token. */
  private mode: "unknown" | "v1" | "v2" = "unknown";
  private cols = 0;
  /** v2: the TUI's wrap rule (§17), fixed with the mode. */
  private rule: LayoutRule = "ink";
  /** v2: the TUI counts a TAB's stops from the content area (§19.7), fixed
   *  with the mode. */
  private contentTabs = false;

  constructor(private readonly opts: ReserveExpandOptions) {}

  /** Feed a raw SSE chunk; resolves to the bytes to relay now. Never rejects. */
  async feed(chunk: string): Promise<string> {
    this.buf += chunk;
    let sep: number;
    while ((sep = this.nextEventBoundary()) >= 0) {
      const end = this.boundaryEnd(sep);
      const raw = this.buf.slice(0, end);
      this.buf = this.buf.slice(end);
      await this.handleEvent(raw);
    }
    return this.drain();
  }

  /** At stream end: every held text released as is, then any partial frame
   *  verbatim. Bytes are never swallowed. */
  end(): string {
    this.releaseAll();
    if (this.buf !== "") {
      this.out.push(this.buf);
      this.buf = "";
    }
    return this.drain();
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private async handleEvent(raw: string): Promise<void> {
    const data = parseData(raw);
    const type = data?.["type"];
    const index = numOr(data?.["index"], -1);

    if (type === "content_block_start") {
      this.release(index); // defensive: an index reused without a stop
      const cb = data?.["content_block"] as Record<string, unknown> | undefined;
      if (cb && cb["type"] === "text") {
        const t = typeof cb["text"] === "string" ? (cb["text"] as string) : "";
        const ctx = newLineContext();
        advanceContext(ctx, t);
        this.blocks.set(index, { held: "", lineStart: t === "" || t.endsWith("\n"), ctx });
      } else {
        this.blocks.delete(index);
      }
      this.out.push(raw);
      return;
    }
    if (type === "content_block_delta") {
      const delta = data?.["delta"] as Record<string, unknown> | undefined;
      const st = this.blocks.get(index);
      if (st && delta && delta["type"] === "text_delta" && typeof delta["text"] === "string") {
        await this.handleText(raw, data!, delta, index, st, delta["text"] as string);
        return;
      }
      this.release(index);
      this.out.push(raw);
      return;
    }
    if (type === "content_block_stop") {
      const st = this.blocks.get(index);
      if (st && st.held !== "") {
        // The held text ends the block: the line ends right after it.
        const region = st.held;
        st.held = "";
        const text = this.mode === "v2"
          ? await this.expandRegionV2(region, "", index, st)
          : await this.expandRegion(region, { lineStart: st.lineStart, textEnd: true }, index);
        this.out.push(textDeltaEvent(index, text));
      }
      this.blocks.delete(index);
      this.out.push(raw);
      return;
    }
    if (type === "message_stop") {
      this.releaseAll();
      this.out.push(raw);
      return;
    }
    this.out.push(raw);
  }

  /** Fix the mode: v2 when the relay paints v2 heads, else v1. */
  private async resolveMode(): Promise<void> {
    if (this.mode !== "unknown") return;
    let cols: number | null = null;
    let rule: LayoutRule = "ink";
    let contentTabs = false;
    if (this.opts.layout && this.opts.shape) {
      try {
        const l = await this.opts.layout();
        if (l && Number.isInteger(l.cols) && l.cols > 0) {
          cols = l.cols;
          if (l.rule === "terminal") rule = "terminal";
          contentTabs = l.tabs === "content";
        }
      } catch {
        cols = null;
      }
    }
    if (cols !== null) {
      this.mode = "v2";
      this.cols = cols;
      this.rule = rule;
      this.contentTabs = contentTabs;
    } else {
      this.mode = "v1";
    }
  }

  private async handleText(
    raw: string,
    data: Record<string, unknown>,
    delta: Record<string, unknown>,
    index: number,
    st: BlockState,
    text: string,
  ): Promise<void> {
    const prefix = st.held;
    const full = prefix + text;
    if (this.mode === "unknown" && (danglingTokenStart(full) < full.length || TOKEN_HINT_RE.test(full))) {
      await this.resolveMode();
    }
    if (this.mode === "v2") {
      await this.handleTextV2(raw, data, delta, index, st, text);
      return;
    }
    // v1 (or no token seen yet), exactly as before.
    st.held = "";
    const nl = full.lastIndexOf("\n");
    const tail = full.slice(nl + 1);
    const tailAtLineStart = nl >= 0 || st.lineStart;
    let region = full;
    if (tail !== "" && tailAtLineStart && danglingTokenStart(tail) === 0) {
      st.held = tail;
      region = full.slice(0, nl + 1);
    }
    if (region === "") return; // all held
    const edges: TextEdges = { lineStart: st.lineStart, textEnd: false };
    st.lineStart = region.endsWith("\n");
    advanceContext(st.ctx, region);
    const outText = await this.expandRegion(region, edges, index);
    if (prefix === "" && region === full && outText === text) {
      this.out.push(raw); // untouched → byte-verbatim
      return;
    }
    this.out.push(serializeEvent("content_block_delta", { ...data, delta: { ...delta, text: outText } }));
  }

  private async handleTextV2(
    raw: string,
    data: Record<string, unknown>,
    delta: Record<string, unknown>,
    index: number,
    st: BlockState,
    text: string,
  ): Promise<void> {
    const prefix = st.held;
    const full = prefix + text;
    st.held = "";
    const k = lineHoldStart(full);
    let region = full;
    let next: string | null = null;
    if (k < full.length) {
      st.held = full.slice(k);
      region = full.slice(0, k);
      next = full[k]!;
    }
    if (region === "") return; // all held
    st.lineStart = region.endsWith("\n");
    const outText = await this.expandRegionV2(region, next, index, st);
    if (prefix === "" && region === full && outText === text) {
      this.out.push(raw); // untouched → byte-verbatim
      return;
    }
    this.out.push(serializeEvent("content_block_delta", { ...data, delta: { ...delta, text: outText } }));
  }

  /** v1: expand the standalone tokens of one region whose shape says ≥ 2
   *  lines. */
  private async expandRegion(region: string, edges: TextEdges, index: number): Promise<string> {
    const cands = standaloneTokens(region, edges);
    if (cands.length === 0) return region;
    const shapes = new Map<string, number>();
    for (const c of cands) {
      if (shapes.has(c.canonical)) continue;
      const n = await this.askLines(c.canonical);
      if (n !== null) shapes.set(c.canonical, n);
    }
    if (shapes.size === 0) return region;
    const out = expandText(region, shapes, this.opts.cap, edges);
    if (out !== region) {
      for (const c of cands) {
        const rows = reserveRows(shapes.get(c.canonical), this.opts.cap);
        if (rows !== 0) await this.commit({ index, token: c.token, hash: c.hash, rows }, c.canonical);
      }
    }
    return out;
  }

  /**
   * v2: walk the tokens of one region, advancing the block's line context
   * over the model's raw text, and expand each eligible one. `next` is the
   * char right after the region ("" = the block ends there; null = unknown,
   * so a token ending the region is not expanded). The hold (lineHoldStart)
   * gives every token here its whole line, so the text after it is known
   * (§14): a `|` there makes the line a table row, and a mid-line block may
   * break it where it would clip.
   */
  private async expandRegionV2(region: string, next: string | null, index: number, st: BlockState): Promise<string> {
    const toks = findTokens(region);
    if (toks.length === 0) {
      advanceContext(st.ctx, region);
      return region;
    }
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
        ...(this.rule !== "ink" ? { rule: this.rule } : {}),
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
      // The content area starts `cols − W` columns in (§11.2: TAB stops),
      // unless the TUI counts its TAB stops from the content area itself
      // (§19.7: Claude Code), which is `indent` 0.
      const indent = !this.contentTabs && this.cols > d.width ? this.cols - d.width : 0;
      s = (await this.opts.shape?.(canonical, d.width, d.first, this.rule !== "ink" ? this.rule : undefined, indent)) ?? null;
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
          ...(this.rule !== "ink" ? { rule: this.rule } : {}),
        }) ?? undefined;
        // The break field widens the head: it must still fit where F put it
        // (Ink lays the head word out; a terminal-rule TUI prints it raw and
        // the filter paints over it, §17).
        if (brk !== undefined && this.rule === "ink" && d.first > 0 &&
          layoutWidth(token) + reserveHeadSuffix(rows, layout, brk).length > d.first) brk = undefined;
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
    // §17: under the terminal rule the text after a one-row value wraps
    // where vanilla's does by itself (a plain token's splice keeps autowrap
    // on past its pad), so no head-only block is sent.
    if (this.rule === "terminal") return null;
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

  /** Release a block's held text as is (not proven eligible). */
  private release(index: number): void {
    const st = this.blocks.get(index);
    if (!st || st.held === "") return;
    const t = st.held;
    st.held = "";
    st.lineStart = t.endsWith("\n");
    advanceContext(st.ctx, t);
    this.out.push(textDeltaEvent(index, t));
  }

  private releaseAll(): void {
    for (const index of [...this.blocks.keys()]) this.release(index);
  }

  private drain(): string {
    if (this.out.length === 0) return "";
    const s = this.out.join("");
    this.out = [];
    return s;
  }

  // SSE framing — mirrors sse-text-repack.ts.

  private nextEventBoundary(): number {
    const lf = this.buf.indexOf("\n\n");
    const crlf = this.buf.indexOf("\r\n\r\n");
    if (lf < 0) return crlf;
    if (crlf < 0) return lf;
    return Math.min(lf, crlf);
  }

  private boundaryEnd(sep: number): number {
    return this.buf.startsWith("\r\n\r\n", sep) ? sep + 4 : sep + 2;
  }
}

function parseData(rawEvent: string): Record<string, unknown> | null {
  const dataLines: string[] = [];
  for (const line of rawEvent.split(/\r?\n/)) {
    if (line.startsWith("data:")) dataLines.push(line.slice("data:".length).replace(/^ /, ""));
  }
  if (dataLines.length === 0) return null;
  try {
    const parsed = JSON.parse(dataLines.join("\n")) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function textDeltaEvent(index: number, text: string): string {
  return serializeEvent("content_block_delta", {
    type: "content_block_delta",
    index,
    delta: { type: "text_delta", text },
  });
}

function serializeEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function numOr(v: unknown, dflt: number): number {
  return typeof v === "number" ? v : dflt;
}

// ── eligibility (the proxy's callbacks) ──────────────────────────────────────

/** The relay state eligibility reads (reply-row-reservation.md §3.6, §11.5). */
export interface ReserveRelay {
  mode: string;
  reserve: boolean;
  /** The terminal's columns (v2 needs it). */
  cols?: number;
  /** The filter paints v2 heads. */
  wrap?: boolean;
  /** The agent's TUI wraps its reply by this rule (§17); absent: `ink`. */
  rule?: string;
  /** Where the agent's TUI counts a reply TAB's stops from (§19.7); absent:
   *  `screen`. */
  tabs?: string;
}

/** The arbiter ops eligibility reads (both optional: absent = no expansion).
 *  Both answer on the HUMAN plane (§5.3, §11.5). */
export interface ReserveArbiter {
  symbolShape?(token: string, opts?: { width: number; first: number; rule?: LayoutRule; indent?: number }): Promise<ReserveShape | null>;
  sessionRelay?(sessionKey: string): Promise<ReserveRelay | null>;
  /** §3.8: record an expanded block (optional; absent = not recorded). */
  noteReserveBlock?(args: { sessionKey: string; token: string; n: number; width?: number; first?: number }): Promise<void>;
}

export interface ReserveEligibilityOptions {
  /** Kill switch (`MANDU_REPLY_RESERVE=0` → false). */
  enabled: boolean;
  /** The session key the reply filter reports under (MANDU_SESSION_KEY). */
  sessionKey?: string;
  /** Deadline for each arbiter call (default 150 ms). */
  timeoutMs?: number;
  /** How long a sessionRelay answer is reused (default 1000 ms). */
  relayTtlMs?: number;
  /** Bounded per-process shape cache (default 4096 entries). */
  shapeCacheMax?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

export const RESERVE_TIMEOUT_MS = 150;
export const RESERVE_RELAY_TTL_MS = 1000;
export const RESERVE_SHAPE_CACHE_MAX = 4096;

const TIMEOUT = Symbol("timeout");

/** `p`, or TIMEOUT after `ms`. Never rejects (a rejection becomes TIMEOUT). */
function withDeadline<T>(p: Promise<T>, ms: number): Promise<T | typeof TIMEOUT> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(TIMEOUT), ms);
    timer.unref?.();
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      () => { clearTimeout(timer); resolve(TIMEOUT); },
    );
  });
}

/** What a relay answer allows: `ok` = expansion at all (PTY, reserve);
 *  `cols` = v2 heads (the filter reports `wrap: true` and its columns);
 *  `rule`, the TUI's wrap rule (§17; anything but `terminal` is `ink`). */
interface RelayVerdict {
  ok: boolean;
  cols: number | null;
  rule: LayoutRule;
  /** The TUI counts a TAB's stops from the content area (§19.7). */
  contentTabs: boolean;
}

/**
 * The eligibility checks of reply-row-reservation.md §3.2 / §11.4 that need
 * the arbiter: the kill switch, the session relayed through a PTY by a
 * filter that paints reserve blocks (cached per session for one second),
 * whether it paints v2 heads (`wrap` and `cols`), and the token's shape
 * (cached for the process lifetime, bounded, keyed by token AND layout).
 * Every failure answers null: no expansion.
 */
export class ReserveEligibility {
  private readonly timeoutMs: number;
  private readonly relayTtlMs: number;
  private readonly shapeCacheMax: number;
  private readonly now: () => number;
  private relay: { at: number; v: RelayVerdict } | null = null;
  private readonly shapes = new Map<string, ReserveShape>();

  constructor(private readonly arbiter: ReserveArbiter, private readonly opts: ReserveEligibilityOptions) {
    this.timeoutMs = opts.timeoutMs ?? RESERVE_TIMEOUT_MS;
    this.relayTtlMs = opts.relayTtlMs ?? RESERVE_RELAY_TTL_MS;
    this.shapeCacheMax = opts.shapeCacheMax ?? RESERVE_SHAPE_CACHE_MAX;
    this.now = opts.now ?? Date.now;
  }

  /** Whether expansion can ever fire here (cheap; no arbiter call). */
  get possible(): boolean {
    return this.opts.enabled && !!this.opts.sessionKey &&
      typeof this.arbiter.symbolShape === "function" && typeof this.arbiter.sessionRelay === "function";
  }

  /** This session's relay verdict (cached; a timeout or error is not). */
  private async relayVerdict(): Promise<RelayVerdict> {
    if (!this.possible) return { ok: false, cols: null, rule: "ink", contentTabs: false };
    const t = this.now();
    if (this.relay && t - this.relay.at < this.relayTtlMs) return this.relay.v;
    const r = await withDeadline(this.arbiter.sessionRelay!(this.opts.sessionKey!), this.timeoutMs);
    // A timeout or error is not cached: the next response asks again.
    if (r === TIMEOUT) return { ok: false, cols: null, rule: "ink", contentTabs: false };
    const ok = r !== null && typeof r === "object" && r.mode === "pty" && r.reserve === true;
    const cols = ok && r!.wrap === true && typeof r!.cols === "number" && Number.isInteger(r!.cols) && r!.cols > 0
      ? r!.cols
      : null;
    const rule: LayoutRule = ok && r!.rule === "terminal" ? "terminal" : "ink";
    const contentTabs = ok && r!.tabs === "content";
    const v = { ok, cols, rule, contentTabs };
    this.relay = { at: t, v };
    return v;
  }

  /** Whether this session's relay paints reserve blocks (cached). */
  async relayReserves(): Promise<boolean> {
    return (await this.relayVerdict()).ok;
  }

  /** The `layout` callback for SseReserveExpander: the relay's columns when
   *  it paints v2 heads, with the TUI's wrap rule (§17) and TAB origin
   *  (§19.7), else null (v1). */
  readonly layout = async (): Promise<{ cols: number; rule?: LayoutRule; tabs?: "content" } | null> => {
    const v = await this.relayVerdict();
    if (!v.ok || v.cols === null) return null;
    return {
      cols: v.cols,
      ...(v.rule !== "ink" ? { rule: v.rule } : {}),
      ...(v.contentTabs ? { tabs: "content" as const } : {}),
    };
  };

  /** One bounded, cached symbolShape call. */
  private async ask(
    token: string, layout?: { width: number; first: number; rule?: LayoutRule; indent?: number },
  ): Promise<ReserveShape | null> {
    const key = layout
      ? `${token}\u0000${layout.width}\u0000${layout.first}\u0000${layout.rule ?? "ink"}\u0000${layout.indent ?? 0}`
      : token;
    const hit = this.shapes.get(key);
    if (hit !== undefined) return hit;
    const call = layout ? this.arbiter.symbolShape!(token, layout) : this.arbiter.symbolShape!(token);
    const r = await withDeadline(call, this.timeoutMs);
    if (r === TIMEOUT || r === null || typeof r !== "object") return null;
    const n = r.lines;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return null;
    const shape: ReserveShape = { lines: n };
    if (layout && typeof r.rows === "number" && Number.isInteger(r.rows) && r.rows >= 0) shape.rows = r.rows;
    if (layout && typeof r.last === "number" && Number.isInteger(r.last) && r.last >= 0) shape.last = r.last;
    if (this.shapes.size >= this.shapeCacheMax) {
      const oldest = this.shapes.keys().next().value;
      if (oldest !== undefined) this.shapes.delete(oldest);
    }
    this.shapes.set(key, shape);
    return shape;
  }

  /** The `lines` callback for SseReserveExpander (v1 heads). */
  readonly lines = async (token: string): Promise<number | null> => {
    if (!(await this.relayReserves())) return null;
    return (await this.ask(token))?.lines ?? null;
  };

  /** The `register` callback for SseReserveExpander (§3.8): record the block
   *  under this session, bounded by the same deadline as every other call.
   *  A timeout or failure is swallowed: the block still goes out. */
  readonly register = async (e: { token: string; rows: number; width?: number; first?: number }): Promise<void> => {
    if (!this.opts.sessionKey || typeof this.arbiter.noteReserveBlock !== "function") return;
    await withDeadline(this.arbiter.noteReserveBlock({
      sessionKey: this.opts.sessionKey, token: e.token, n: e.rows,
      ...(e.width !== undefined && e.first !== undefined ? { width: e.width, first: e.first } : {}),
    }), this.timeoutMs);
  };

  /** The `shape` callback for SseReserveExpander (v2 heads). */
  readonly shape = async (
    token: string, width: number, first: number, rule?: LayoutRule, indent?: number,
  ): Promise<ReserveShape | null> => {
    if (!(await this.relayReserves())) return null;
    return this.ask(token, {
      width, first,
      ...(rule !== undefined && rule !== "ink" ? { rule } : {}),
      // Sent only when it moves a TAB stop: 0 is the arbiter's default.
      ...(indent !== undefined && Number.isInteger(indent) && indent > 0 ? { indent } : {}),
    });
  };
}
