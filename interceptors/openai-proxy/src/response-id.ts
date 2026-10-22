/**
 * response-id — the provider's id of the response an agent received on an
 * OpenAI-family wire (Chat Completions `chatcmpl-…`, Responses `resp_…`),
 * read off the bytes the proxy writes to the agent, for the `tllm_call`
 * event's `model.responseId`: the agents keep the same id in their own
 * records, and `mandu scan` joins a past session to Mandu on it
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 6).
 *
 * ONE MODULE, TWO COPIES, like text-repack.ts: copied VERBATIM to
 *   interceptors/anthropic-proxy/src/response-id.ts  (the routed OpenClaw /
 *        OpenCode / Goose `openai` providers, agent-e2e-harness.md §9)
 *   interceptors/openai-proxy/src/response-id.ts     (its Chat Completions
 *        route; its Responses route reads the id in transcript.ts)
 * tests/stack/transcript-scan.test.ts fails unless both are byte-identical.
 * Change the anthropic-proxy copy and copy it out.
 *
 * Which id: the one the agent keeps. OpenClaw's Chat reader keeps the first
 * chunk's `id` (`responseId ||= chunk.id`), the AI SDK OpenCode uses takes
 * the first chunk's, and Goose its chunks' (one id per stream from every
 * provider seen); on Responses, OpenClaw and the AI SDK take
 * `response.created`'s `response.id`. So: Chat, the first event whose data
 * has an `id`; Responses, the first `response.*` event carrying
 * `response.id`; a buffered body, its `id`. The first such id decides: an
 * ill-formed one (`responseIdOf`'s charset) gives none, never a later one.
 * The sniffer reads what the agent is sent AFTER the proxy's gates, so a
 * chunk the gate dropped or a synthetic chunk it released is counted as the
 * agent saw it.
 *
 * Observability only, never on the security path: it reads strings it is
 * handed and changes nothing; it keeps at most one partial event (up to
 * MAX_PENDING bytes) until it decides, then stops reading; it never throws.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (2026-10-21).
 */
import { responseIdOf } from "./events.js";

/** The OpenAI-family wires whose answer carries a response id. */
export type ResponseIdWire = "chat" | "responses";

/** Bytes of one undecided partial event kept; past it the id is given up. */
const MAX_PENDING = 1024 * 1024;

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

/** A buffered (non-streamed) answer's id: the body's `id`, well formed. */
export function responseIdOfBody(body: unknown): string | undefined {
  return isObj(body) ? responseIdOf(body["id"]) : undefined;
}

/** The id one parsed SSE event carries for `wire`; `null` when the event
 *  carries none (look further). */
function eventId(wire: ResponseIdWire, ev: Json): unknown {
  if (wire === "chat") {
    const id = ev["id"];
    return id === undefined || id === null || id === "" ? null : id;
  }
  if (typeof ev["type"] !== "string" || !ev["type"].startsWith("response.")) return null;
  const r = ev["response"];
  if (!isObj(r)) return null;
  const id = r["id"];
  return id === undefined || id === null || id === "" ? null : id;
}

/** Reads the response id off a streamed answer, as the agent is sent it. */
export class ResponseIdSniffer {
  private buf = "";
  private decided = false;
  private id: string | undefined;

  constructor(private readonly wire: ResponseIdWire) {}

  /** Text written to the agent, in order. */
  feed(text: string): void {
    if (this.decided || text === "") return;
    try {
      this.buf += text;
      for (;;) {
        const lf = this.buf.indexOf("\n\n");
        const crlf = this.buf.indexOf("\r\n\r\n");
        const sep = lf < 0 ? crlf : crlf < 0 ? lf : Math.min(lf, crlf);
        if (sep < 0) break;
        const raw = this.buf.slice(0, sep);
        this.buf = this.buf.slice(this.buf.startsWith("\r\n\r\n", sep) ? sep + 4 : sep + 2);
        this.event(raw);
        if (this.decided) return;
      }
      if (this.buf.length > MAX_PENDING) this.decide(undefined);
    } catch {
      this.decide(undefined);
    }
  }

  /** The id, once the answer ended: undefined when it carried none or an
   *  ill-formed one. */
  value(): string | undefined {
    return this.id;
  }

  private decide(v: unknown): void {
    this.decided = true;
    this.buf = "";
    this.id = responseIdOf(v);
  }

  private event(raw: string): void {
    const data: string[] = [];
    for (const line of raw.split(/\r?\n/)) if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    if (data.length === 0) return;
    const text = data.join("\n");
    if (text.trim() === "[DONE]") return;
    let ev: unknown;
    try { ev = JSON.parse(text); } catch { return; }
    if (!isObj(ev)) return;
    const id = eventId(this.wire, ev);
    if (id !== null) this.decide(id);
  }
}
