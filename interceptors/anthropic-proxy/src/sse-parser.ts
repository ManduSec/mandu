/**
 * sse-parser — reconstruct tool_use decisions + the assistant TEXT reply from
 *   the model→agent response.
 *
 * Mandu Track A (interceptors/anthropic-proxy). The response side of the boundary
 * (mandu.md §3, plan §4, build-spec step 6): Anthropic streams the Messages
 * response as Server-Sent Events. We parse the stream to reconstruct each
 * tool_use block (name + accumulated input JSON) so the proxy can call arbiter
 * recordToolCall(...) — letting the OS interceptors (Track B / M3) correlate a
 * later openat/connect/execve to a known tool decision.
 *
 * CRITICAL: this parser is OBSERVE-ONLY. The proxy passes the raw response
 * bytes through to the client UNCHANGED (the response path is not a security
 * boundary for symbolization — symbols flow OUT to the agent unchanged; the
 * data-USAGE/egress gate is M3). We only sniff the stream to record decisions.
 *
 * SSE framing (hand-rolled, zero deps): events are separated by a blank line;
 * within an event, lines are `field: value`. Anthropic uses `event:` and
 * `data:` lines, each `data:` carrying one JSON object. The relevant sequence
 * per tool_use block:
 *   content_block_start { index, content_block: { type:"tool_use", id, name } }
 *   content_block_delta { index, delta: { type:"input_json_delta", partial_json }}
 *   content_block_stop  { index }
 * We accumulate partial_json per index and JSON.parse the assembled string at
 * stop (or message_stop). Robust to deltas split across network chunks.
 */

export interface ReconstructedToolUse {
  id: string;
  name: string;
  /** Parsed input. If the accumulated JSON failed to parse, `input` is the raw
   * accumulated string under `__rawInputJson` and `inputParseError` is set. */
  input: unknown;
  inputParseError?: string;
}

interface PartialBlock {
  index: number;
  id: string;
  name: string;
  jsonParts: string[];
}

/**
 * Incrementally-fed SSE parser. Feed it response chunks (string); it emits
 * fully-reconstructed tool_use blocks via the onToolUse callback as soon as
 * their content_block_stop arrives. Call `end()` to flush any block left open
 * (e.g. a stream cut short before content_block_stop).
 */
export class SseToolUseParser {
  private buf = "";
  /** Open tool_use blocks keyed by stream index. */
  private readonly open = new Map<number, PartialBlock>();
  private readonly emitted = new Set<string>();
  /** Accumulated assistant TEXT deltas (the model's visible reply), in order —
   *  captured alongside tool_use so the tllm_call event carries real output. */
  private readonly textParts: string[] = [];
  /** The response's id from `message_start` (`message.id`), unchecked: the
   *  event builder keeps it only when it is well formed. */
  private msgId: string | undefined;

  constructor(private readonly onToolUse: (tu: ReconstructedToolUse) => void) {}

  /** Feed a chunk of the raw SSE byte stream (already decoded to string). */
  feed(chunk: string): void {
    this.buf += chunk;
    // SSE events are delimited by a blank line ("\n\n"). Tolerate CRLF.
    let sep: number;
    // Normalize CRLF to LF for boundary scanning only (we don't forward this).
    while ((sep = this.nextEventBoundary()) >= 0) {
      const rawEvent = this.buf.slice(0, sep);
      // Advance past the boundary (handle both \n\n and \r\n\r\n).
      this.buf = this.buf.slice(this.boundaryEnd(sep));
      this.handleEvent(rawEvent);
    }
  }

  /** Flush at stream end: emit any still-open block on a best-effort basis. */
  end(): void {
    // A trailing event without a blank-line terminator.
    if (this.buf.trim() !== "") {
      this.handleEvent(this.buf);
      this.buf = "";
    }
    for (const blk of this.open.values()) {
      this.emit(blk);
    }
    this.open.clear();
  }

  /** The assistant's visible text reply reconstructed from text_delta events
   *  (empty string if the turn was tool_use-only). */
  assistantText(): string {
    return this.textParts.join("");
  }

  /** The response's id (`message_start`'s `message.id`), the one the agent's
   *  transcript keeps (confidentiality-plan-17 §3 item 6); undefined when
   *  the stream carried none. */
  messageId(): string | undefined {
    return this.msgId;
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private nextEventBoundary(): number {
    const lf = this.buf.indexOf("\n\n");
    const crlf = this.buf.indexOf("\r\n\r\n");
    if (lf < 0) return crlf;
    if (crlf < 0) return lf;
    return Math.min(lf, crlf);
  }

  private boundaryEnd(sep: number): number {
    // If the boundary at `sep` is CRLFCRLF, skip 4 chars, else 2.
    if (this.buf.startsWith("\r\n\r\n", sep)) return sep + 4;
    return sep + 2;
  }

  private handleEvent(rawEvent: string): void {
    // Collect all `data:` payloads in the event (Anthropic uses one per event).
    const dataLines: string[] = [];
    for (const line of rawEvent.split(/\r?\n/)) {
      if (line.startsWith("data:")) {
        dataLines.push(line.slice("data:".length).replace(/^ /, ""));
      }
    }
    if (dataLines.length === 0) return;
    const dataStr = dataLines.join("\n");
    if (dataStr === "[DONE]") return;

    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(dataStr) as Record<string, unknown>;
    } catch {
      return; // ignore non-JSON / keepalive comments
    }
    this.handleData(obj);
  }

  private handleData(obj: Record<string, unknown>): void {
    const type = obj["type"];
    switch (type) {
      case "message_start": {
        const m = obj["message"] as Record<string, unknown> | undefined;
        if (this.msgId === undefined && m && typeof m["id"] === "string") this.msgId = m["id"];
        break;
      }
      case "content_block_start": {
        const index = numOr(obj["index"], -1);
        const cb = obj["content_block"] as Record<string, unknown> | undefined;
        if (cb && cb["type"] === "tool_use") {
          this.open.set(index, {
            index,
            id: typeof cb["id"] === "string" ? (cb["id"] as string) : "",
            name: typeof cb["name"] === "string" ? (cb["name"] as string) : "",
            jsonParts: [],
          });
          // Anthropic may include a non-empty `input` object on start (rare);
          // seed it as a JSON part so accumulation still works.
          if (cb["input"] && typeof cb["input"] === "object" &&
              Object.keys(cb["input"] as object).length > 0) {
            this.open.get(index)!.jsonParts.push(JSON.stringify(cb["input"]));
          }
        }
        break;
      }
      case "content_block_delta": {
        const index = numOr(obj["index"], -1);
        const delta = obj["delta"] as Record<string, unknown> | undefined;
        // Assistant TEXT (the model's visible reply) lives in its OWN block, not
        // in `open` (that map tracks tool_use). Accumulate regardless of `open`.
        if (delta && delta["type"] === "text_delta" && typeof delta["text"] === "string") {
          this.textParts.push(delta["text"] as string);
          break;
        }
        const blk = this.open.get(index);
        if (!blk) break;
        if (delta && delta["type"] === "input_json_delta" &&
            typeof delta["partial_json"] === "string") {
          blk.jsonParts.push(delta["partial_json"] as string);
        }
        break;
      }
      case "content_block_stop": {
        const index = numOr(obj["index"], -1);
        const blk = this.open.get(index);
        if (blk) {
          this.emit(blk);
          this.open.delete(index);
        }
        break;
      }
      case "message_stop": {
        // Flush anything still open (defensive).
        for (const blk of this.open.values()) this.emit(blk);
        this.open.clear();
        break;
      }
      default:
        break;
    }
  }

  private emit(blk: PartialBlock): void {
    if (this.emitted.has(blk.id) && blk.id !== "") return;
    this.emitted.add(blk.id);
    const joined = blk.jsonParts.join("");
    if (joined.trim() === "") {
      // No input deltas → empty-object input.
      this.onToolUse({ id: blk.id, name: blk.name, input: {} });
      return;
    }
    try {
      this.onToolUse({ id: blk.id, name: blk.name, input: JSON.parse(joined) });
    } catch (err) {
      this.onToolUse({
        id: blk.id,
        name: blk.name,
        input: { __rawInputJson: joined },
        inputParseError: (err as Error).message,
      });
    }
  }
}

function numOr(v: unknown, dflt: number): number {
  return typeof v === "number" ? v : dflt;
}

/**
 * Extract tool_use blocks from a NON-streaming Messages response object (the
 * `content` array). Used when the upstream response is buffered JSON, not SSE.
 */
export function extractToolUsesFromJson(resp: unknown): ReconstructedToolUse[] {
  const out: ReconstructedToolUse[] = [];
  if (!resp || typeof resp !== "object") return out;
  const content = (resp as { content?: unknown }).content;
  if (!Array.isArray(content)) return out;
  for (const b of content) {
    if (b && typeof b === "object" && (b as { type?: string }).type === "tool_use") {
      const blk = b as { id?: string; name?: string; input?: unknown };
      out.push({
        id: typeof blk.id === "string" ? blk.id : "",
        name: typeof blk.name === "string" ? blk.name : "",
        input: blk.input ?? {},
      });
    }
  }
  return out;
}
