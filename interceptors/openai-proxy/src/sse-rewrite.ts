/**
 * sse-rewrite — transform the model's shell-command decisions in the
 * model→agent Responses SSE stream: the Phase-0 exec gate (exec-routing.md
 * §3) composed with the P4 forward path-map (fs-sync.md §1.3).
 *
 * Mandu Track A (interceptors/openai-proxy). Codex streams the model's tool
 * call as a sequence of Responses events; the command appears in FOUR
 * payload-bearing events, and Codex acts on the assembled item, so all must
 * be transformed CONSISTENTLY. Two wires (responses-types.ts header):
 *
 *   the classic function_call (codex ≤ 0.136):
 *   response.function_call_arguments.delta   {item_id, output_index, delta}
 *   response.function_call_arguments.done    {item_id, output_index, arguments}
 *   response.output_item.done                {item:{type:"function_call", arguments}}
 *   response.completed                       {response:{output:[{…function_call…}]}}
 *
 *   the script cell (codex ≥ 0.154, a `custom_tool_call` named `exec` whose
 *   `input` is JavaScript carrying `tools.exec_command({…})` literals —
 *   script-cell.ts):
 *   response.custom_tool_call_input.delta    {item_id, output_index, delta}
 *   response.custom_tool_call_input.done     {item_id, output_index, input}
 *   response.output_item.done                {item:{type:"custom_tool_call", input}}
 *   response.completed                       {response:{output:[{…custom_tool_call…}]}}
 *
 * A path or a command can span DELTA fragments, so the deltas are BUFFERED per
 * item_id and NOT emitted incrementally; at `.done` the full payload is
 * transformed and re-emitted as ONE synthetic delta + the transformed `.done`
 * (the same buffer-and-re-emit-as-one-delta shape as the anthropic-proxy). The
 * item snapshots in `.output_item.done` / `.completed` carry the full payload,
 * so they are transformed in place as they stream.
 *
 * The transform is `argsGate` (exec gate — BLOCK a symbol-in-command-position,
 * fail-closed) THEN the view map (forward path-map), applied to an arguments
 * JSON string; a script cell is transformed literal by literal through the
 * same function (transformScriptCell). Both halves are optional: the exec gate
 * needs no map, so this runs even on a non-worktree launch. `feed`/`end` are
 * ASYNC because the exec gate awaits an arbiter verdict at the assembly
 * points; the caller chains chunk processing to preserve output order.
 *
 * Every assembled call is also REPORTED once (`onCall`) so the proxy can emit
 * the `tool_use` observability event the anthropic-proxy has always emitted —
 * best-effort, after the bytes are decided, never on the security path.
 *
 * CONSERVATIVE BY CONSTRUCTION (rule 3): an event whose payload does not parse
 * / does not change re-emits the ORIGINAL bytes; every non-payload event passes
 * through VERBATIM. The map direction is not the symbolization boundary — its
 * fail-safe is "no rewrite"; the exec gate, being a security gate, fails CLOSED
 * inside `argsGate` (a blocked command becomes a benign `exit 77` sentinel,
 * and a script cell whose exec arguments the gate cannot read becomes the
 * sentinel cell).
 */

import { blockSentinelCell, scriptCellExecCalls, transformScriptCell } from "./script-cell.js";
import { cellPatchCalls } from "./cell-patch-calls.js";
import { blockNoticeText } from "./exec-gate.js";
import type { ViewMap } from "./view-map.js";

/** The call an arguments payload belongs to: its `call_id` (null when the
 *  stream named none) and the function it calls (`exec_command` for a script
 *  cell's exec literal). Plan 13 D9 follow-up: the exec gate sends the id to
 *  the arbiter and the proxy records the delivered command under it. */
export interface CallContext {
  callId: string | null;
  name: string;
  /** A function_call's `namespace` (codex ≥ 0.154: an MCP server's
   *  `mcp__<server>`), when the stream named one: the call goes by
   *  `<namespace>__<name>` (rewrite-request.ts codexToolName). */
  namespace?: string;
  /** The stream's item id, when known (the order of a response's calls,
   *  unmapped-upload.ts UploadTurn). */
  itemId?: string;
  /** An exec literal inside a code-mode cell (`callId` is then the CELL's
   *  id): the cell, not the literal, is what Codex echoes back as history
   *  (exec-history.ts). */
  inCell?: boolean;
}

/** The function a script cell's exec literals call (script-cell.ts). */
export const SCRIPT_EXEC_LITERAL = "exec_command";

/** Transform an assembled function_call `arguments` JSON string: return the
 * rewritten JSON, or null to keep the original bytes. Composes the exec gate +
 * the view map; MUST NOT throw (fail-closed/fail-safe handled inside). `call`
 * names the call when the rewriter knows it. */
export type ArgsTransform = (argumentsJson: string, call?: CallContext) => Promise<string | null>;

/** One tool call the stream carried, as the model wrote it (before any
 *  rewrite): a function_call's name + arguments, each `tools.exec_command`
 *  literal of a script cell (name `exec_command`) and each of its literal
 *  `tools.apply_patch` calls, or a freeform patch call, a patch's text as
 *  `{"input": …}` (`freeformCalls`). */
export interface ToolCallSeen {
  itemId: string;
  callId: string | null;
  name: string;
  argumentsJson: string;
}

/** Codex's freeform (custom) tools whose text is the call's whole input,
 *  not a script: `apply_patch`, whose patch names the files it touches
 *  (dashboard.md §4.25b "A patch names its files"). */
export const FREEFORM_INPUT_TOOLS: ReadonlySet<string> = new Set(["apply_patch"]);

/**
 * The calls one freeform (custom_tool_call) item reports, as the model wrote
 * it. A freeform input tool (`apply_patch`) is ONE call whose arguments are
 * `{"input": <its text>}`, the field its JSON form (Codex's function tool,
 * OpenClaw's) carries the same patch in, so every form reads alike
 * downstream; before 2026-10-09 it reported nothing, and a patch whose
 * content held a `tools.exec_command(…)` literal reported that as a shell
 * call. Any other freeform tool (the code-mode `exec` cell, `js_repl`)
 * reports each exec literal it runs (script-cell.ts), then each
 * `tools.apply_patch(…)` whose patch is a literal, in that patch record's
 * shape (cell-patch-calls.ts; before 2026-10-17 a patch in a cell was no
 * call, dashboard.md §4.25b "A patch in a code cell"). Observability only:
 * the gate reads the item itself, never this.
 */
export function freeformCalls(name: string, input: string): Array<{ name: string; argsJson: string }> {
  if (FREEFORM_INPUT_TOOLS.has(name)) return [{ name, argsJson: JSON.stringify({ input }) }];
  return [...scriptCellExecCalls(input), ...cellPatchCalls(input)];
}

export interface RewriterOptions {
  /** A script cell whose exec arguments are not one JSON literal: `block`
   *  (the exec gate is active — replace the cell by the sentinel cell) or
   *  `keep` (path-map only — leave it). Default `keep`. */
  unparseable?: "block" | "keep";
  /** Reported once per assembled call (deduped across the snapshots). */
  onCall?: (call: ToolCallSeen) => void;
  log?: (msg: string) => void;
  /** The whole-cell gate and the isolation fact (script-cell.ts
   *  TransformScriptCellOptions; plan 10 §11.13 path (a)). */
  cellGate?: (src: string) => Promise<string | null>;
  cellsIsolated?: boolean;
  /** A code-mode cell was replaced WHOLE by the sentinel cell: its call id
   *  (null when the stream named none) and the notice it prints (script-cell.ts
   *  `onCellBlocked`; plan 10 §11.8). */
  onCellBlocked?: (callId: string | null, notice: string) => void;
  /** Plan 10 §11.18, the cell guard (cell-guard.ts): given a code-mode
   *  `exec` cell as it will be delivered, the cell with the run-time guard at
   *  its head, or null to deliver it as it is (an identified cell, the axis
   *  off). A guard that fails leaves the cell unguarded, which keeps the
   *  request side's text rules (fail-closed there). */
  cellGuard?: (src: string) => Promise<string | null>;
  /** A code-mode cell's text as the model wrote it and as it is delivered,
   *  once per cell the rewriter transformed (exec-history.ts: the model reads
   *  back its own cell when the exec gate rewrote it). A record only. */
  onCellDelivered?: (callId: string | null, original: string, delivered: string) => void;
  /** The unmapped upload leg over a code cell (unmapped-upload.ts
   *  gateUnmappedUploadCell), asked before every other cell rule: the
   *  notice when a file the cell names is held (the WHOLE cell is then
   *  replaced by the sentinel cell, which prints it), or null. A throw holds
   *  the cell (fail-closed). */
  cellUploadGate?: (src: string, call: CallContext | undefined) => Promise<string | null>;
  /** Told once per call item, in stream order, BEFORE its payload is gated
   *  (unmapped-upload.ts UploadTurn: the window rule's order). A record
   *  only, never throws into the rewriter. */
  onItem?: (call: CallContext) => void;
}

/** Report a transformed cell (`onCellDelivered`); a record only, never throws. */
function reportCell(opts: RewriterOptions, callId: string | null, original: string, delivered: string | null): void {
  if (delivered === null || !opts.onCellDelivered) return;
  try { opts.onCellDelivered(callId, original, delivered); } catch { /* a record only */ }
}

/** The code-mode cell tool the cell guard applies to (mcp-cell.ts). */
const GUARDED_CELL_TOOL = "exec";

/** Apply the cell guard to a delivered cell: the guarded text, or null. */
async function guardDelivered(opts: RewriterOptions, name: string, src: string): Promise<string | null> {
  if (!opts.cellGuard || name !== GUARDED_CELL_TOOL) return null;
  try {
    return await opts.cellGuard(src);
  } catch (err) {
    opts.log?.(`cell guard failed (${(err as Error).message}); the cell goes unguarded and keeps the text rules`);
    return null;
  }
}

/** The unmapped upload leg over a cell (`cellUploadGate`): the sentinel
 *  cell that replaces it when a file it names is held (its notice told to
 *  `onCellBlocked`), or null to go on. A throw holds the cell. */
async function uploadHeldCell(opts: RewriterOptions, src: string, call: CallContext | undefined): Promise<string | null> {
  if (!opts.cellUploadGate) return null;
  let held: string | null;
  try {
    held = await opts.cellUploadGate(src, call);
  } catch (err) {
    held = `mandu-upload-gate: the cell was not run: Mandu could not check the files it names (${(err as Error).message}) — fail closed`;
  }
  if (held === null) return null;
  opts.log?.(`script-cell: BLOCKED a cell that would send a held local file (${held.slice(0, 200)})`);
  try { opts.onCellBlocked?.(call?.callId ?? null, blockNoticeText(held)); } catch { /* a record only */ }
  return blockSentinelCell(held);
}

interface ItemMeta { type: string; name: string; callId: string | null; namespace?: string }

export class ResponsesArgsRewriter {
  private buf = "";
  /** Accumulated function_call argument deltas per open item_id. */
  private readonly argDeltas = new Map<string, string>();
  /** Accumulated custom_tool_call input deltas per open item_id. */
  private readonly inputDeltas = new Map<string, string>();
  /** output_index for each open item_id (to re-emit the synthetic delta). */
  private readonly outputIndex = new Map<string, number>();
  /** What `.output_item.added` said an item is (type / name / call_id). */
  private readonly itemMeta = new Map<string, ItemMeta>();
  /** Items already reported through onCall. */
  private readonly reported = new Set<string>();
  private out: string[] = [];

  /** Memoize the transform per DISTINCT payload. The same command arrives in
   * up to three payload-bearing snapshots (`.done`, `.output_item.done`,
   * `.completed`); gating/mapping it once (a) keeps the arbiter call +
   * `exec_action` event single per command and (b) guarantees the three
   * snapshots stay consistent. */
  private readonly transformCache = new Map<string, string | null>();
  private readonly scriptCache = new Map<string, string | null>();
  /** The cell guard's answer per delivered cell text. */
  private readonly guardCache = new Map<string, string | null>();

  /** `transform` composes the exec gate + forward path-map over an assembled
   * arguments JSON string (null ⇒ keep the original). */
  constructor(private readonly transform: ArgsTransform, private readonly opts: RewriterOptions = {}) {}

  private async applyTransform(argumentsJson: string, call?: CallContext): Promise<string | null> {
    // Keyed by the call too: two calls with the same arguments are each
    // gated and recorded under their own id (plan 13 D9 follow-up).
    const key = `${call?.callId ?? ""}\u0000${argumentsJson}`;
    const cached = this.transformCache.get(key);
    if (cached !== undefined) return cached;
    const result = await this.transform(argumentsJson, call);
    this.transformCache.set(key, result);
    return result;
  }

  private async applyScript(input: string, call?: CallContext): Promise<string | null> {
    // A patch is not code: nothing in its text runs, so neither the cell
    // gate nor the exec-literal rule reads it (its JSON form, a
    // function_call, is not gated either). Before 2026-10-09 a patch in a
    // session the gate held became the sentinel cell, which is no patch.
    if (call && FREEFORM_INPUT_TOOLS.has(call.name)) return null;
    const key = `${call?.callId ?? ""}\u0000${input}`;
    const cached = this.scriptCache.get(key);
    if (cached !== undefined) return cached;
    // The unmapped upload leg first (unmapped-upload.ts): a file a call of
    // the cell would send is held, and the whole cell becomes the sentinel
    // cell printing why (as the exec gate's whole-cell block).
    const blocked = await uploadHeldCell(this.opts, input, call);
    if (blocked !== null) {
      this.scriptCache.set(key, blocked);
      reportCell(this.opts, call?.callId ?? null, input, blocked);
      return blocked;
    }
    const literal: CallContext | undefined = call ? { callId: call.callId, name: SCRIPT_EXEC_LITERAL, inCell: true } : undefined;
    const onCellBlocked = this.opts.onCellBlocked;
    const transformed = await transformScriptCell(input, (args) => this.applyTransform(args, literal), {
      unparseable: this.opts.unparseable ?? "keep",
      log: this.opts.log,
      ...(this.opts.cellGate ? { cellGate: this.opts.cellGate } : {}),
      ...(this.opts.cellsIsolated !== undefined ? { cellsIsolated: this.opts.cellsIsolated } : {}),
      ...(onCellBlocked ? { onCellBlocked: (notice: string) => onCellBlocked(call?.callId ?? null, notice) } : {}),
    });
    // The cell guard, over the cell as it will be delivered, once per text
    // (every snapshot of the item carries the same guard).
    const delivered = transformed ?? input;
    let guarded = this.guardCache.get(delivered);
    if (guarded === undefined) {
      guarded = await guardDelivered(this.opts, call?.name ?? "", delivered);
      this.guardCache.set(delivered, guarded);
    }
    const result = guarded ?? transformed;
    this.scriptCache.set(key, result);
    reportCell(this.opts, call?.callId ?? null, input, result);
    return result;
  }

  /** The call an item id belongs to, as `.output_item.added` (or the item
   *  snapshot itself) named it. */
  private callOf(itemId: string, item?: Record<string, unknown>): CallContext {
    const meta = this.itemMeta.get(itemId);
    const namespace = typeof item?.["namespace"] === "string" ? (item["namespace"] as string) : meta?.namespace;
    return {
      callId: typeof item?.["call_id"] === "string" ? (item["call_id"] as string) : (meta?.callId ?? null),
      name: typeof item?.["name"] === "string" ? (item["name"] as string) : (meta?.name ?? ""),
      ...(namespace !== undefined && namespace !== "" ? { namespace } : {}),
      ...(itemId !== "" ? { itemId } : {}),
    };
  }

  /** Report an assembled call once, BEFORE its payload is gated (`onItem`,
   *  then `onCall`). `payload` is the model's ORIGINAL text. */
  private report(itemId: string, kind: "function_call" | "custom_tool_call", payload: string, item?: Record<string, unknown>): void {
    if (this.reported.has(itemId)) return;
    this.reported.add(itemId);
    if (this.opts.onItem) {
      try { this.opts.onItem(this.callOf(itemId, item)); } catch { /* a record only */ }
    }
    if (!this.opts.onCall) return;
    const meta = this.itemMeta.get(itemId);
    const callId = typeof item?.["call_id"] === "string" ? (item["call_id"] as string) : (meta?.callId ?? null);
    const name = typeof item?.["name"] === "string" ? (item["name"] as string) : (meta?.name ?? "");
    try {
      if (kind === "function_call") {
        this.opts.onCall({ itemId, callId, name, argumentsJson: payload });
      } else {
        for (const c of freeformCalls(name, payload)) this.opts.onCall({ itemId, callId, name: c.name, argumentsJson: c.argsJson });
      }
    } catch { /* observability only */ }
  }

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

  /** Flush at stream end. A stream cut after all deltas but before `.done` still
   * has the FULL payload in hand (the accumulation), so transform it rather
   * than releasing raw HumanView paths / an un-gated command that Codex would
   * run. Emit the transformed payload as one delta + a synthetic `.done`; if
   * the accumulation does not parse (a true mid-JSON cut) fall back to the raw
   * bytes (conservative "no rewrite", never swallow). */
  async end(): Promise<string> {
    for (const [itemId, accumulated] of this.argDeltas) {
      const idx = this.outputIndex.get(itemId) ?? 0;
      if (accumulated === "") continue;
      this.report(itemId, "function_call", accumulated);
      const transformed = await this.applyTransform(accumulated, this.callOf(itemId));
      const finalArgs = transformed ?? accumulated;
      this.out.push(serialize("response.function_call_arguments.delta", {
        type: "response.function_call_arguments.delta",
        item_id: itemId,
        output_index: idx,
        delta: finalArgs,
      }));
      // Close the item so Codex can finalize the (transformed) function_call —
      // its real `.done` never arrived.
      this.out.push(serialize("response.function_call_arguments.done", {
        type: "response.function_call_arguments.done",
        item_id: itemId,
        output_index: idx,
        arguments: finalArgs,
      }));
    }
    for (const [itemId, accumulated] of this.inputDeltas) {
      const idx = this.outputIndex.get(itemId) ?? 0;
      if (accumulated === "") continue;
      this.report(itemId, "custom_tool_call", accumulated);
      const transformed = await this.applyScript(accumulated, this.callOf(itemId));
      const finalInput = transformed ?? accumulated;
      this.out.push(serialize("response.custom_tool_call_input.delta", {
        type: "response.custom_tool_call_input.delta",
        item_id: itemId,
        output_index: idx,
        delta: finalInput,
      }));
      this.out.push(serialize("response.custom_tool_call_input.done", {
        type: "response.custom_tool_call_input.done",
        item_id: itemId,
        output_index: idx,
        input: finalInput,
      }));
    }
    this.argDeltas.clear();
    this.inputDeltas.clear();
    this.outputIndex.clear();
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
    let eventName = "";
    for (const line of rawEvent.split(/\r?\n/)) {
      if (line.startsWith("event:")) eventName = line.slice("event:".length).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice("data:".length).replace(/^ /, ""));
    }
    if (dataLines.length === 0) return null;
    try {
      const parsed = JSON.parse(dataLines.join("\n")) as unknown;
      if (!parsed || typeof parsed !== "object") return null;
      const obj = parsed as Record<string, unknown>;
      if (eventName && obj["type"] === undefined) obj["type"] = eventName;
      return obj;
    } catch {
      return null;
    }
  }

  /** Transform one output item snapshot (a function_call's `arguments` or a
   *  custom_tool_call's `input`); null when unchanged / not a call item. */
  private async transformItem(item: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    const itemId = typeof item["id"] === "string" ? (item["id"] as string) : "";
    if (item["type"] === "function_call" && typeof item["arguments"] === "string") {
      this.report(itemId, "function_call", item["arguments"] as string, item);
      const transformed = await this.applyTransform(item["arguments"] as string, this.callOf(itemId, item));
      return transformed !== null ? { ...item, arguments: transformed } : null;
    }
    if (item["type"] === "custom_tool_call" && typeof item["input"] === "string") {
      this.report(itemId, "custom_tool_call", item["input"] as string, item);
      const transformed = await this.applyScript(item["input"] as string, this.callOf(itemId, item));
      return transformed !== null ? { ...item, input: transformed } : null;
    }
    return null;
  }

  private async handleEvent(raw: string): Promise<void> {
    const data = this.parseData(raw);
    const type = typeof data?.["type"] === "string" ? (data!["type"] as string) : "";

    switch (type) {
      case "response.output_item.added": {
        const item = data!["item"] as Record<string, unknown> | undefined;
        if (item && typeof item["id"] === "string") {
          this.itemMeta.set(item["id"] as string, {
            type: String(item["type"] ?? ""),
            name: typeof item["name"] === "string" ? (item["name"] as string) : "",
            callId: typeof item["call_id"] === "string" ? (item["call_id"] as string) : null,
            ...(typeof item["namespace"] === "string" ? { namespace: item["namespace"] as string } : {}),
          });
        }
        break;
      }
      case "response.function_call_arguments.delta":
      case "response.custom_tool_call_input.delta": {
        // Buffer; do NOT emit (a path/command may span deltas).
        const store = type === "response.function_call_arguments.delta" ? this.argDeltas : this.inputDeltas;
        const itemId = String(data!["item_id"] ?? "");
        const delta = typeof data!["delta"] === "string" ? (data!["delta"] as string) : "";
        store.set(itemId, (store.get(itemId) ?? "") + delta);
        if (data!["output_index"] !== undefined && typeof data!["output_index"] === "number") {
          this.outputIndex.set(itemId, data!["output_index"] as number);
        }
        return;
      }
      case "response.function_call_arguments.done":
      case "response.custom_tool_call_input.done": {
        const isScript = type === "response.custom_tool_call_input.done";
        const store = isScript ? this.inputDeltas : this.argDeltas;
        const field = isScript ? "input" : "arguments";
        const itemId = String(data!["item_id"] ?? "");
        const hasString = typeof data![field] === "string";
        const buffered = store.get(itemId);
        // Nothing to (re)assemble: the `.done` carries no string payload AND
        // no deltas were buffered. Relay the ORIGINAL event VERBATIM (rule 3).
        if (!hasString && (buffered === undefined || buffered === "")) {
          store.delete(itemId);
          this.outputIndex.delete(itemId);
          this.out.push(raw);
          return;
        }
        const full = hasString ? (data![field] as string) : (buffered as string);
        const idx = typeof data!["output_index"] === "number"
          ? (data!["output_index"] as number)
          : (this.outputIndex.get(itemId) ?? 0);
        this.report(itemId, isScript ? "custom_tool_call" : "function_call", full);
        const transformed = isScript ? await this.applyScript(full, this.callOf(itemId)) : await this.applyTransform(full, this.callOf(itemId));
        const finalPayload = transformed ?? full;
        // The real deltas were withheld (a path/command may span them), so
        // re-emit the assembled payload as ONE synthetic delta + the done
        // event, both carrying the (possibly) transformed payload.
        const deltaType = isScript ? "response.custom_tool_call_input.delta" : "response.function_call_arguments.delta";
        this.out.push(serialize(deltaType, {
          type: deltaType,
          item_id: itemId,
          output_index: idx,
          delta: finalPayload,
        }));
        this.out.push(serialize(type, { ...data, [field]: finalPayload }));
        store.delete(itemId);
        this.outputIndex.delete(itemId);
        return;
      }
      case "response.output_item.done": {
        const item = data!["item"] as Record<string, unknown> | undefined;
        if (item) {
          const transformed = await this.transformItem(item);
          if (transformed !== null) {
            this.out.push(serialize(type, { ...data, item: transformed }));
            return;
          }
        }
        break;
      }
      case "response.completed": {
        const resp = data!["response"] as Record<string, unknown> | undefined;
        const output = resp?.["output"];
        if (Array.isArray(output)) {
          let changed = false;
          const newOutput: unknown[] = [];
          for (const it of output) {
            if (it && typeof it === "object") {
              const transformed = await this.transformItem(it as Record<string, unknown>);
              if (transformed !== null) {
                changed = true;
                newOutput.push(transformed);
                continue;
              }
            }
            newOutput.push(it);
          }
          if (changed) {
            this.out.push(serialize(type, { ...data, response: { ...resp, output: newOutput } }));
            return;
          }
        }
        break;
      }
      default:
        break;
    }

    // Default: relay the event VERBATIM.
    this.out.push(raw);
  }
}

/** Compose the exec gate (`argsGate`) THEN the forward path-map into one
 * ArgsTransform. Either may be absent. Returns null when neither changed the
 * arguments (caller re-emits the original bytes). */
export function composeArgsTransform(
  map: ViewMap | null,
  argsGate?: ArgsTransform,
): ArgsTransform {
  return async (argumentsJson: string, call?: CallContext): Promise<string | null> => {
    let base = argumentsJson;
    let changed = false;
    if (argsGate) {
      const gated = await argsGate(base, call);
      if (gated !== null) { base = gated; changed = true; }
    }
    if (map) {
      const mapped = map.rewriteFunctionCallArguments(base, "forward");
      if (mapped !== null) { base = mapped; changed = true; }
    }
    return changed ? base : null;
  };
}

/**
 * Transform every call item of a buffered (stream:false) Response `output[]`
 * in place — the JSON twin of the stream path, sharing its item rule. Returns
 * whether anything changed.
 */
export async function transformOutputItems(
  output: unknown[],
  transform: ArgsTransform,
  opts: RewriterOptions = {},
): Promise<boolean> {
  let changed = false;
  for (const it of output) {
    if (!it || typeof it !== "object") continue;
    const item = it as Record<string, unknown>;
    const itemId = typeof item["id"] === "string" ? (item["id"] as string) : "";
    if (item["type"] === "function_call" && typeof item["arguments"] === "string") {
      const callId = typeof item["call_id"] === "string" ? (item["call_id"] as string) : null;
      const call: CallContext = {
        callId, name: String(item["name"] ?? ""),
        ...(typeof item["namespace"] === "string" && item["namespace"] !== "" ? { namespace: item["namespace"] as string } : {}),
        ...(itemId !== "" ? { itemId } : {}),
      };
      try { opts.onItem?.(call); } catch { /* a record only */ }
      opts.onCall?.({ itemId, callId, name: String(item["name"] ?? ""), argumentsJson: item["arguments"] as string });
      const rewritten = await transform(item["arguments"] as string, call);
      if (rewritten !== null) { item["arguments"] = rewritten; changed = true; }
    } else if (item["type"] === "custom_tool_call" && typeof item["input"] === "string") {
      const cell: CallContext = { callId: typeof item["call_id"] === "string" ? (item["call_id"] as string) : null, name: String(item["name"] ?? ""), ...(itemId !== "" ? { itemId } : {}) };
      try { opts.onItem?.(cell); } catch { /* a record only */ }
      for (const c of freeformCalls(String(item["name"] ?? ""), item["input"] as string)) {
        opts.onCall?.({ itemId, callId: typeof item["call_id"] === "string" ? (item["call_id"] as string) : null, name: c.name, argumentsJson: c.argsJson });
      }
      // A patch is not code (the stream path's applyScript says why).
      if (FREEFORM_INPUT_TOOLS.has(String(item["name"] ?? ""))) continue;
      const cellCall: CallContext = { callId: typeof item["call_id"] === "string" ? (item["call_id"] as string) : null, name: SCRIPT_EXEC_LITERAL, inCell: true };
      const original = item["input"] as string;
      const held = await uploadHeldCell(opts, original, cell);
      if (held !== null) {
        item["input"] = held;
        changed = true;
        reportCell(opts, cellCall.callId, original, held);
        continue;
      }
      const rewritten = await transformScriptCell(item["input"] as string, (args) => transform(args, cellCall), {
        unparseable: opts.unparseable ?? "keep", log: opts.log,
        ...(opts.cellGate ? { cellGate: opts.cellGate } : {}),
        ...(opts.cellsIsolated !== undefined ? { cellsIsolated: opts.cellsIsolated } : {}),
        ...(opts.onCellBlocked ? { onCellBlocked: (notice: string) => opts.onCellBlocked!(cellCall.callId, notice) } : {}),
      });
      const guarded = await guardDelivered(opts, String(item["name"] ?? ""), rewritten ?? (item["input"] as string));
      if (guarded !== null) { item["input"] = guarded; changed = true; } else if (rewritten !== null) { item["input"] = rewritten; changed = true; }
      reportCell(opts, cellCall.callId, original, guarded ?? rewritten);
    }
  }
  return changed;
}

/** Serialize one Responses SSE event in `event:`+`data:` framing. */
function serialize(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}
