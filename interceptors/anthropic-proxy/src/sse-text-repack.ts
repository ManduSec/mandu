/**
 * sse-text-repack — re-segment text_delta events so a `$MDU:` symbol token is
 * never split across deltas (model→agent SSE stream).
 *
 * Mandu Track A (interceptors/anthropic-proxy).
 *
 * WHY THIS EXISTS (kills a leak class AT THE SOURCE): the model's reply text
 * streams as arbitrary BPE-boundary fragments — `$MDU:inspect[695b]` and
 * `.result` routinely arrive in SEPARATE content_block_delta events (live:
 * session 1783831380-3877123, both turns). The agent TUI paints each delta
 * batch as a frame with status/spinner rows interleaved BELOW the text, so
 * the token's halves reach the terminal with other content between them —
 * and no downstream stream filter can reassemble that: the reply-filter must
 * emit bytes in order, so once the bare base is followed by frame furniture
 * it is on the wire before `.result` exists anywhere
 * (interceptors/reply-filter/src/filter.ts candidateCut documents the
 * residual). HERE the token is BORN into the stream as pure text — no ANSI,
 * no frames — so the boundary decision is exact: hold a delta's trailing
 * possible-in-flight-token suffix and prepend it to the block's next
 * text_delta. The agent then receives every token WHOLE inside one delta and
 * renders it contiguously; the reply-filter's chunk-hold covers what remains
 * (raw PTY read splits of contiguous bytes).
 *
 * CONTENT-PRESERVING BY CONSTRUCTION: only text_delta SEGMENTATION changes —
 * the concatenated block text is byte-identical, and SSE consumers already
 * tolerate arbitrary segmentation (the upstream segments at BPE whim). All
 * other events relay verbatim, in order. A held suffix flushes before its
 * block's stop / any other same-block event, at message_stop, and at end():
 * bytes are never swallowed. Utility posture (the same as reply-filter):
 * this is NOT the symbolization boundary — a held suffix that turns out to
 * be ordinary prose ("total: $" + "5.00") just moves to the next delta.
 *
 * The SSE framing helpers mirror sse-rewrite.ts (kept local so each
 * transformer stays self-contained). The token grammar (`danglingTokenStart`)
 * lives in text-repack.ts, the OpenAI-wire repacker shared verbatim with
 * interceptors/openai-proxy, so every repacker cuts by the same rule.
 */

import { danglingTokenStart } from "./text-repack.js";

export class SseTextDeltaRepacker {
  private buf = "";
  /** Held dangling-token suffix per content-block index. */
  private readonly held = new Map<number, string>();
  private out: string[] = [];

  /** Feed a raw SSE chunk; returns the bytes to relay downstream right now.
   *  Pure string work — never throws, never awaits. */
  feed(chunk: string): string {
    this.buf += chunk;
    let sep: number;
    while ((sep = this.nextEventBoundary()) >= 0) {
      const end = this.boundaryEnd(sep);
      const raw = this.buf.slice(0, end); // KEEP the terminator for verbatim relay
      this.buf = this.buf.slice(end);
      this.handleEvent(raw);
    }
    return this.drain();
  }

  /** Flush at stream end: every held suffix is released as its own
   *  text_delta, then any partial trailing frame verbatim — bytes are never
   *  swallowed. */
  end(): string {
    this.flushAll();
    if (this.buf !== "") {
      this.out.push(this.buf);
      this.buf = "";
    }
    return this.drain();
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private handleEvent(raw: string): void {
    const data = this.parseData(raw);
    const type = data?.["type"];

    if (type === "content_block_delta") {
      const index = numOr(data?.["index"], -1);
      const delta = data?.["delta"] as Record<string, unknown> | undefined;
      if (delta && delta["type"] === "text_delta" && typeof delta["text"] === "string") {
        this.handleTextDelta(raw, data!, delta, index, delta["text"] as string);
        return;
      }
      // A non-text delta for this block (citations, …): the held text
      // precedes it in the block's stream — flush first, then relay.
      this.flushHeld(index);
      this.out.push(raw);
      return;
    }
    if (type === "content_block_stop" || type === "content_block_start") {
      // stop: the block's text is over — release the suffix before it.
      // start: defensive (an index reused without a stop — malformed stream).
      this.flushHeld(numOr(data?.["index"], -1));
      this.out.push(raw);
      return;
    }
    if (type === "message_stop") {
      this.flushAll();
      this.out.push(raw);
      return;
    }
    this.out.push(raw); // pings, message_delta, keepalives, unknown: verbatim
  }

  private handleTextDelta(
    raw: string,
    data: Record<string, unknown>,
    delta: Record<string, unknown>,
    index: number,
    text: string,
  ): void {
    const prefix = this.held.get(index) ?? "";
    this.held.delete(index);
    const full = prefix + text;
    const cut = danglingTokenStart(full);
    const head = full.slice(0, cut);
    if (cut < full.length) this.held.set(index, full.slice(cut));
    if (head === "") return; // the whole delta is a growing candidate — held
    if (prefix === "" && cut === full.length) {
      this.out.push(raw); // untouched → byte-verbatim fast path
      return;
    }
    this.out.push(serializeEvent("content_block_delta", { ...data, delta: { ...delta, text: head } }));
  }

  private flushHeld(index: number): void {
    const t = this.held.get(index);
    if (t === undefined) return;
    this.held.delete(index);
    this.out.push(
      serializeEvent("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "text_delta", text: t },
      }),
    );
  }

  private flushAll(): void {
    for (const index of [...this.held.keys()]) this.flushHeld(index);
  }

  private drain(): string {
    if (this.out.length === 0) return "";
    const s = this.out.join("");
    this.out = [];
    return s;
  }

  // SSE framing — mirrors sse-rewrite.ts byte-for-byte.

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

  private parseData(rawEvent: string): Record<string, unknown> | null {
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
}

/** Serialize one SSE event in Anthropic's `event:`+`data:` framing (mirrors
 *  sse-rewrite.ts). */
function serializeEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function numOr(v: unknown, dflt: number): number {
  return typeof v === "number" ? v : dflt;
}
