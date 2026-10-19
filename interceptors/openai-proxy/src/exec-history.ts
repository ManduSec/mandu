/**
 * exec-history — the model reads back the call it wrote, not the exec gate's
 * rewrite of it (confidentiality.md §4, "What the model reads back"; the
 * openai-proxy twin of the anthropic-proxy's net-gate.ts NetGateHistory).
 *
 * Mandu Track A (interceptors/openai-proxy). The exec gate rewrites a Codex
 * call on its way to Codex: a blocked command becomes the `exit 77` block
 * sentinel (a function_call's command, a code-mode cell's exec literal, or
 * the whole cell replaced by the sentinel cell), and an allowed command whose
 * secret placeholder the shell would expand is delivered REQUOTED
 * (confidentiality.md §7). Codex keeps what it received and echoes it back as
 * history on every later request, so without this the model reads a past in
 * which it wrote `echo 'mandu-exec-gate: blocked …'; exit 77` itself (Claude
 * Code's model, live 2026-10-11, apologized four times for "a fake Mandu
 * block" and retried), or the requoted form, which it then copies, and which
 * is not the command a HIGH session's approval names.
 *
 * So the rewrite stays where it enforces (the wire to Codex, which is what
 * runs) and is undone where it only misinforms (the request to the model).
 *
 * SECURITY: what is put back is the text the model itself streamed for that
 * call id, captured from the model's own response before any transform
 * touched it: model-authored text returning to the model that wrote it. No
 * tool output, no resolved value and no HumanView byte enters the context
 * this way; nothing is resolved and no table is read. It cannot un-mask a
 * placeholder: the openai-proxy never resolves a placeholder in a call (the
 * requote only inserts `'` and `\` beside it, the sentinel only removes), so
 * the model's text carries every placeholder exactly as it wrote it, and the
 * request side never masks a call's arguments or a cell's text (its masking
 * boundary is the tool OUTPUT and the user's text), so there is no mask in
 * that place to undo. A call is restored only when its call id is one this
 * proxy rewrote AND the echoed payload still equals the form this proxy
 * delivered for it (byte for byte; a function_call's arguments as the same
 * JSON value), so nothing else in the history can be altered through it. The
 * restore runs AFTER the request rewrite, so the call's output is still
 * classified against the command that actually ran.
 *
 * UTILITY-ONLY and in memory: a proxy restart forgets the record and the
 * history reads as the delivered form again (the pre-2026-10-12 behavior),
 * never worse. Enforcement never depends on it: Codex ran the delivered form,
 * and the next call the model writes is gated afresh.
 */

import { isCustomToolCallItem, isFunctionCallItem, type ResponsesRequest } from "./responses-types.js";

/** Remembered calls are bounded; the oldest is dropped first. */
export const EXEC_HISTORY_MAX = 512;

/** The two call items whose payload the exec gate rewrites. */
export type GatedCallKind = "function_call" | "custom_tool_call";

interface Remembered {
  /** The model's own payload (a function_call's `arguments`, a cell's `input`). */
  original: string;
  /** The payload this proxy delivered to Codex for that call. */
  delivered: string;
}

/** Two `arguments` strings carry the same JSON value (whitespace aside). */
function sameArguments(a: string, b: string): boolean {
  if (a === b) return true;
  try {
    return JSON.stringify(JSON.parse(a)) === JSON.stringify(JSON.parse(b));
  } catch {
    return false;
  }
}

export class ExecGateHistory {
  private readonly calls = new Map<string, Remembered>();
  /** Call ids the exec gate rewrote in this exchange, not yet delivered. */
  private readonly gated = new Set<string>();

  private static key(kind: GatedCallKind, callId: string): string {
    return `${kind}\u0000${callId}`;
  }

  /** The exec gate rewrote (blocked or requoted) part of call `callId`: its
   *  delivered payload, once known, is remembered (`delivered`). */
  markGated(callId: string | null | undefined): void {
    if (!callId) return;
    this.gated.delete(callId);
    this.gated.add(callId);
    while (this.gated.size > EXEC_HISTORY_MAX) {
      const oldest = this.gated.values().next().value;
      if (oldest === undefined) break;
      this.gated.delete(oldest);
    }
  }

  /** The payload delivered to Codex for call `callId`, beside the model's own
   *  `original`. Remembered only when the exec gate rewrote that call
   *  (`markGated`) and the two differ. NEVER throws. */
  delivered(kind: GatedCallKind, callId: string | null | undefined, original: string, delivered: string): void {
    if (!callId || !this.gated.has(callId)) return;
    this.gated.delete(callId);
    if (typeof original !== "string" || typeof delivered !== "string" || original === delivered) return;
    const key = ExecGateHistory.key(kind, callId);
    this.calls.delete(key);
    this.calls.set(key, { original, delivered });
    while (this.calls.size > EXEC_HISTORY_MAX) {
      const oldest = this.calls.keys().next().value;
      if (oldest === undefined) break;
      this.calls.delete(oldest);
    }
  }

  /** Put the model's own payload back on every remembered call of a
   *  Responses request (or a Chat Completions request's Responses shadow),
   *  in place. Returns the call ids restored. NEVER throws. */
  restore(req: ResponsesRequest): string[] {
    const restored: string[] = [];
    if (this.calls.size === 0) return restored;
    try {
      const input = Array.isArray(req.input) ? req.input : [];
      for (const item of input) {
        if (isFunctionCallItem(item) && typeof item.call_id === "string" && typeof item.arguments === "string") {
          const known = this.calls.get(ExecGateHistory.key("function_call", item.call_id));
          if (!known || !sameArguments(item.arguments, known.delivered)) continue;
          item.arguments = known.original;
          restored.push(item.call_id);
        } else if (isCustomToolCallItem(item) && typeof item.call_id === "string" && typeof item.input === "string") {
          const known = this.calls.get(ExecGateHistory.key("custom_tool_call", item.call_id));
          if (!known || item.input !== known.delivered) continue;
          item.input = known.original;
          restored.push(item.call_id);
        }
      }
    } catch { /* utility-only */ }
    return restored;
  }
}
