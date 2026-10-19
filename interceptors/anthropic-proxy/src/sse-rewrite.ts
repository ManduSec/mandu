/**
 * sse-rewrite — forward-map tool_use path args in the model→agent SSE stream.
 *
 * Mandu Track A (interceptors/anthropic-proxy). P2 of the portable fs core
 * (fs-sync.md §1.3 rule 5): `tool_use` args arrive as partial-JSON
 * deltas, so path fields cannot be rewritten chunk-by-chunk. This transformer
 * BUFFERS each tool_use content block (start → input_json_delta* → stop),
 * applies the ViewMap's registry-driven forward rewrite to the assembled
 * input, and re-emits the block with the whole rewritten input as ONE
 * input_json_delta. Everything else — text blocks, message events, pings,
 * unknown event types — passes through VERBATIM, byte-for-byte.
 *
 * Ordering is preserved exactly: from the moment any tool_use block is open,
 * ALL events are queued and flushed in arrival order once every open block
 * closes (Anthropic streams content blocks sequentially, so in practice the
 * queue holds one block's events plus the odd ping).
 *
 * CONSERVATIVE BY CONSTRUCTION (rules 3): a tool outside the registry, an
 * input that fails to parse, or a rewrite that changes nothing re-emits the
 * ORIGINAL buffered bytes untouched. The response direction is not the
 * symbolization boundary — the fail-safe here is "no rewrite" (degrading to
 * CWD scoping + the context backstop), never "guess".
 *
 * The proxy feeds the REWRITTEN output to both the client and the tool_use
 * sniffer (sse-parser.ts), so recordToolCall + events capture what the agent
 * actually received — the form the OS interceptors will see in syscalls.
 *
 * The rewrite itself is an injected ASYNC callback (`ToolInputTransform`): the
 * proxy composes the P2 forward map with the P3 sensitive-path gate (which
 * awaits an arbiter verdict per out-of-workspace path), so this module stays a
 * pure SSE-framing transformer with no policy knowledge.
 */

/**
 * Rewrite one assembled tool_use input. Return null OR {changed:false} to
 * re-emit the ORIGINAL buffered bytes verbatim; {changed:true} to re-emit the
 * block with `input` as one delta. MUST NOT throw (the caller composes
 * fail-safe/fail-closed behavior inside the callback). `toolUseId` is the
 * block's id, for event correlation (empty string when absent).
 */
export type ToolInputTransform = (
  name: string,
  input: unknown,
  toolUseId: string,
) => Promise<{ input: unknown; changed: boolean } | null>;

/** One parsed-enough SSE event: the raw bytes plus its JSON `data` if any. */
interface BufferedEvent {
  raw: string;
  data: Record<string, unknown> | null;
}

export class SseToolUseRewriter {
  private buf = "";
  /** Indexes of tool_use blocks currently open (being buffered). */
  private readonly openToolUse = new Set<number>();
  /** Event queue while any tool_use block is open (preserves global order). */
  private queue: BufferedEvent[] = [];
  private out: string[] = [];

  constructor(private readonly rewriteInput: ToolInputTransform) {}

  /** Feed a raw SSE chunk; returns the bytes to relay downstream right now. */
  async feed(chunk: string): Promise<string> {
    this.buf += chunk;
    let sep: number;
    while ((sep = this.nextEventBoundary()) >= 0) {
      const end = this.boundaryEnd(sep);
      const raw = this.buf.slice(0, end); // KEEP the terminator for verbatim relay
      this.buf = this.buf.slice(end);
      await this.handleEvent(raw);
    }
    return this.drain();
  }

  /**
   * Flush at stream end. Any still-queued tool_use block is finalized
   * FAIL-CLOSED: assembled and put through the transform (P2 map + P3 gate) and
   * re-emitted closed with a SYNTHETIC stop, or DROPPED when its assembled
   * input does not parse. A queued block is NEVER released un-transformed — a
   * stream cut short mid-block cannot hand the agent an un-mapped/un-gated
   * tool_use (fs-sync.md §1.4.1: the gate fails closed, it does not fall
   * through to raw). A partial trailing event (an incomplete SSE frame, never a
   * complete tool_use) is released verbatim so bytes are never swallowed.
   */
  async end(): Promise<string> {
    if (this.queue.length > 0) await this.drainQueue(true);
    this.openToolUse.clear();
    if (this.buf !== "") {
      this.out.push(this.buf);
      this.buf = "";
    }
    return this.drain();
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private drain(): string {
    if (this.out.length === 0) return "";
    const s = this.out.join("");
    this.out = [];
    return s;
  }

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

  /** Parse the event's `data:` JSON (null for keepalives / non-JSON). */
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

  private async handleEvent(raw: string): Promise<void> {
    const data = this.parseData(raw);
    const type = data?.["type"];

    if (type === "content_block_start") {
      const cb = data?.["content_block"] as Record<string, unknown> | undefined;
      if (cb && cb["type"] === "tool_use") {
        this.openToolUse.add(numOr(data?.["index"], -1));
        this.queue.push({ raw, data });
        return;
      }
    } else if (type === "content_block_stop" && this.openToolUse.has(numOr(data?.["index"], -1))) {
      const index = numOr(data?.["index"], -1);
      this.queue.push({ raw, data });
      this.openToolUse.delete(index);
      if (this.openToolUse.size === 0) await this.flushQueue();
      return;
    }

    if (this.openToolUse.size > 0) {
      // A block is being buffered: queue EVERYTHING to preserve global order.
      this.queue.push({ raw, data });
      // message_stop with a block left open (malformed stream): finalize the
      // queue FAIL-CLOSED — the open block is rewritten+gated (or dropped),
      // never released verbatim (that would hand the agent an un-mapped,
      // un-gated tool_use for exactly the sensitive path the P3 gate exists to
      // stop). The message_stop itself relays after the finalized block.
      if (type === "message_stop") {
        await this.drainQueue(true);
        this.openToolUse.clear();
      }
      return;
    }

    this.out.push(raw); // fast path: nothing buffered, relay verbatim
  }

  /** All open blocks closed normally: rewrite each buffered tool_use block. */
  private async flushQueue(): Promise<void> {
    await this.drainQueue(false);
  }

  /**
   * Emit the queued events in order, rewriting each tool_use block.
   *
   * `finalizing` distinguishes the two entry points. Normal flush (false) runs
   * only once every open block has its content_block_stop, so every block is
   * complete. Finalization (true) runs at abnormal termination (message_stop
   * with a block still open, or stream end): a block may lack its stop event,
   * and such a block is closed FAIL-CLOSED — transformed + capped with a
   * synthetic stop when its input parses, DROPPED when it does not — so an
   * un-transformed tool_use never reaches the agent.
   */
  private async drainQueue(finalizing: boolean): Promise<void> {
    const queue = this.queue;
    this.queue = [];

    // Group the queued events per tool_use block index for assembly, keeping
    // every event's queue position so ordering survives re-emission.
    for (let i = 0; i < queue.length; i++) {
      const e = queue[i];
      const type = e.data?.["type"];
      if (type !== "content_block_start") {
        // Deltas/stops belonging to a rewritten block were consumed below;
        // whatever remains (pings, message_delta, foreign blocks) relays as-is.
        if (!e.data?.["__consumed"]) this.out.push(e.raw);
        continue;
      }
      const cb = e.data?.["content_block"] as Record<string, unknown> | undefined;
      if (!cb || cb["type"] !== "tool_use") {
        this.out.push(e.raw);
        continue;
      }
      const index = numOr(e.data?.["index"], -1);

      // Collect this block's deltas + stop from the remainder of the queue.
      const parts: string[] = [];
      const members: BufferedEvent[] = [];
      // A non-empty seed input on the start event joins the accumulation,
      // mirroring sse-parser.ts.
      if (cb["input"] && typeof cb["input"] === "object" && Object.keys(cb["input"] as object).length > 0) {
        parts.push(JSON.stringify(cb["input"]));
      }
      let stopEvent: BufferedEvent | null = null;
      for (let j = i + 1; j < queue.length; j++) {
        const q = queue[j];
        const qType = q.data?.["type"];
        if (numOr(q.data?.["index"], -999) !== index) continue;
        if (qType === "content_block_delta") {
          const delta = q.data?.["delta"] as Record<string, unknown> | undefined;
          if (delta && delta["type"] === "input_json_delta" && typeof delta["partial_json"] === "string") {
            parts.push(delta["partial_json"] as string);
          }
          members.push(q);
        } else if (qType === "content_block_stop") {
          stopEvent = q;
          break;
        }
      }

      const assembled = parts.join("");
      const rw = await this.tryRewrite(String(cb["name"] ?? ""), assembled, String(cb["id"] ?? ""));

      // Mark this block's already-queued members (+ any stop) consumed so the
      // outer loop never re-relays them regardless of the branch taken below.
      const consume = (): void => {
        for (const mEvt of members) (mEvt.data as Record<string, unknown>)["__consumed"] = true;
        if (stopEvent) (stopEvent.data as Record<string, unknown>)["__consumed"] = true;
      };

      if (stopEvent !== null) {
        // Complete block (normal flush): rewrite, or re-emit the ORIGINAL bytes
        // when there is nothing to change / the input does not parse (rule 3 —
        // a model that sent itself invalid JSON just fails at the client, no
        // gate was skipped). Members + stop relay verbatim via the outer loop.
        if (rw.status === "rewritten") {
          this.emitBlock(e.data, cb, index, rw.json, stopEvent.raw);
          consume();
        } else {
          this.out.push(e.raw);
        }
        continue;
      }

      // No stop event ⇒ an OPEN block reached here only via finalization
      // (abnormal termination). Fail closed: a parseable input is transformed
      // (map + gate) and capped with a SYNTHETIC stop so the agent receives the
      // GATED/MAPPED form; an unparseable (truncated) input is DROPPED entirely,
      // since it can be neither mapped nor gated and must not reach the agent
      // raw. Either way the original start + deltas are suppressed.
      consume();
      if (rw.status === "unparseable") continue; // drop: emit nothing for the block
      const json = rw.status === "rewritten" ? rw.json : assembled;
      this.emitBlock(e.data, cb, index, json, this.syntheticStop(index));
    }
  }

  /** Re-emit one tool_use block: start (input zeroed) + ONE delta carrying the
   * whole (rewritten or assembled) input + the given stop event bytes. */
  private emitBlock(
    startData: Record<string, unknown> | null,
    cb: Record<string, unknown>,
    index: number,
    inputJson: string,
    stopRaw: string,
  ): void {
    const sd = { ...startData, content_block: { ...cb, input: {} } };
    delete (sd as Record<string, unknown>)["__consumed"];
    this.out.push(serializeEvent("content_block_start", sd));
    this.out.push(
      serializeEvent("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "input_json_delta", partial_json: inputJson },
      }),
    );
    this.out.push(stopRaw);
  }

  /** A synthetic content_block_stop for `index`, used to close a block whose
   * real stop never arrived (abnormal termination). */
  private syntheticStop(index: number): string {
    return serializeEvent("content_block_stop", { type: "content_block_stop", index });
  }

  /**
   * Apply the injected transform to one assembled input JSON. Three-way result:
   *   "rewritten"   — the transform changed the input; `json` is the new form;
   *   "unchanged"   — unknown tool, empty name, or nothing to change (the block
   *                   is safe to re-emit as-is: nothing needed mapping/gating);
   *   "unparseable" — the assembled input is not valid JSON (rule 3: never
   *                   rewrite what we cannot parse; on finalization, drop it).
   */
  private async tryRewrite(
    name: string,
    inputJson: string,
    toolUseId: string,
  ): Promise<{ status: "rewritten"; json: string } | { status: "unchanged" } | { status: "unparseable" }> {
    if (name === "") return { status: "unchanged" };
    let input: unknown = {};
    if (inputJson.trim() !== "") {
      try {
        input = JSON.parse(inputJson);
      } catch {
        return { status: "unparseable" };
      }
    }
    const r = await this.rewriteInput(name, input, toolUseId);
    if (r === null || !r.changed) return { status: "unchanged" };
    return { status: "rewritten", json: JSON.stringify(r.input) };
  }
}

/** Serialize one SSE event in Anthropic's `event:`+`data:` framing. */
function serializeEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function numOr(v: unknown, dflt: number): number {
  return typeof v === "number" ? v : dflt;
}
