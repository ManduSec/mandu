/** HumanView JSON egress; see docs/design/ui/reply-row-reservation.md §15.
 * A bounded JSON parser retains source spans instead of reserializing metadata.
 * It deliberately has no symbol parser: decoded human strings go to the arbiter.
 */
import type { ReplyArbiter } from "./arbiter-client.js";

type Node =
  | { kind: "string"; value: string; start: number; end: number }
  | { kind: "object"; fields: Map<string, Node> }
  | { kind: "array"; items: Node[] }
  | { kind: "scalar" };
type StringNode = Extract<Node, { kind: "string" }>;
export type StructuredDiagnostic = "malformed-record" | "record-limit" | "unknown-schema" | "resolution-failed";
export interface StructuredOptions {
  maxRecordBytes?: number;
  maxOutputBytes?: number;
  resolutionTimeoutMs?: number;
  onDiagnostic?: (reason: StructuredDiagnostic) => void;
  onResolve?: (before: string, after: string) => void | Promise<void>;
}
const MAX_DEPTH = 64;
const MAX_NODES = 20_000;
const MAX_FIELDS = 128;

function parseSpans(source: string): Node {
  let pos = 0;
  let nodes = 0;
  const whitespace = (): void => { while (/[\x20\t\r\n]/.test(source[pos] ?? "!")) pos++; };
  const string = (): StringNode => {
    const start = pos++;
    while (pos < source.length) {
      const char = source[pos++];
      if (char === "\\") { pos++; continue; }
      if (char === '"') {
        const value: unknown = JSON.parse(source.slice(start, pos));
        if (typeof value !== "string") throw new Error();
        return { kind: "string", value, start, end: pos };
      }
    }
    throw new Error();
  };
  const value = (depth: number): Node => {
    if (depth > MAX_DEPTH || ++nodes > MAX_NODES) throw new Error();
    whitespace();
    if (source[pos] === '"') return string();
    if (source[pos] === "{" || source[pos] === "[") {
      const object = source[pos++] === "{";
      const end = object ? "}" : "]";
      const fields = new Map<string, Node>();
      const items: Node[] = [];
      whitespace();
      if (source[pos] !== end) {
        for (;;) {
          whitespace();
          if (object) {
            if (source[pos] !== '"') throw new Error();
            const key = string().value;
            if (fields.has(key)) throw new Error();
            whitespace();
            if (source[pos++] !== ":") throw new Error();
            fields.set(key, value(depth + 1));
          } else items.push(value(depth + 1));
          whitespace();
          if (source[pos] !== ",") break;
          pos++;
        }
      }
      if (source[pos++] !== end) throw new Error();
      return object ? { kind: "object", fields } : { kind: "array", items };
    }
    const scalar = /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y;
    scalar.lastIndex = pos;
    const match = scalar.exec(source);
    if (!match) throw new Error();
    pos = scalar.lastIndex;
    return { kind: "scalar" };
  };
  const result = value(0);
  whitespace();
  if (pos !== source.length) throw new Error();
  return result;
}
function field(node: Node | undefined, name: string): Node | undefined {
  return node?.kind === "object" ? node.fields.get(name) : undefined;
}
function isString(node: Node | undefined, value: string): boolean {
  return node?.kind === "string" && node.value === value;
}
/** No recursive string walking: only these completed human-content shapes. */
function humanFields(record: Node): StringNode[] | null {
  if (isString(field(record, "type"), "result")) {
    const result = field(record, "result");
    return result?.kind === "string" ? [result] : null;
  }
  if (isString(field(record, "type"), "assistant")) {
    const message = field(record, "message");
    const content = field(message, "content");
    if (!isString(field(message, "role"), "assistant") || content?.kind !== "array") return null;
    const strings: StringNode[] = [];
    for (const block of content.items) {
      if (!isString(field(block, "type"), "text")) continue;
      const text = field(block, "text");
      if (text?.kind !== "string") return null;
      strings.push(text);
    }
    return strings;
  }
  return null;
}

export class StructuredReplyFilter {
  private tail = "";
  private tailBytes = 0;
  private oversized = false;
  private readonly maxRecordBytes: number;
  private readonly maxOutputBytes: number;
  constructor(
    private readonly arbiter: Pick<ReplyArbiter, "desymbolize">,
    private readonly format: "json" | "stream-json",
    private readonly opts: StructuredOptions = {},
  ) {
    this.maxRecordBytes = opts.maxRecordBytes ?? 1024 * 1024;
    this.maxOutputBytes = opts.maxOutputBytes ?? 4 * 1024 * 1024;
  }
  get pending(): number { return this.tail.length; }
  /** Bytes taken in but not yet emitted (ReplyStreamFilter.held's shape; a
   *  structured stream never feeds a screen model: pipe mode only). */
  get held(): number { return this.tail.length; }
  private diagnostic(reason: StructuredDiagnostic): void {
    try { this.opts.onDiagnostic?.(reason); } catch { /* observability only */ }
  }
  async write(chunk: string): Promise<string> {
    let out = "";
    let offset = 0;
    while (offset < chunk.length) {
      const nl = this.format === "stream-json" ? chunk.indexOf("\n", offset) : -1;
      const end = nl < 0 ? chunk.length : nl + 1;
      const part = chunk.slice(offset, end);
      const size = Buffer.byteLength(part, "utf8");
      if (this.oversized || this.tailBytes + size > this.maxRecordBytes) {
        if (!this.oversized) this.diagnostic("record-limit");
        this.oversized = true;
        out += this.tail + part;
        this.tail = "";
        this.tailBytes = 0;
      } else {
        this.tail += part;
        this.tailBytes += size;
        if (nl >= 0) {
          out += await this.record(this.tail);
          this.tail = "";
          this.tailBytes = 0;
        }
      }
      if (nl >= 0) this.oversized = false;
      offset = end;
    }
    return out;
  }
  async flush(final = true): Promise<string> {
    if (!final) return "";
    const tail = this.tail;
    this.tail = "";
    this.tailBytes = 0;
    return tail === "" ? "" : this.record(tail);
  }
  private async record(source: string): Promise<string> {
    if (source.trim() === "") return source;
    let root: Node;
    try { root = parseSpans(source); } catch { this.diagnostic("malformed-record"); return source; }
    const records = this.format === "json" && root.kind === "array" ? root.items : [root];
    const targets: StringNode[] = [];
    for (const record of records) {
      const fields = humanFields(record);
      if (fields === null) this.diagnostic("unknown-schema");
      else targets.push(...fields);
    }
    if (targets.length > MAX_FIELDS) { this.diagnostic("record-limit"); return source; }
    const patches: { node: StringNode; text: string }[] = [];
    let bytes = Buffer.byteLength(source, "utf8");
    const deadline = Date.now() + (this.opts.resolutionTimeoutMs ?? 2000);
    try {
      for (const node of targets) {
        if (!node.value.includes("$MDU:")) continue;
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error();
        let timer: ReturnType<typeof setTimeout> | undefined;
        let resolved: string;
        try {
          resolved = await Promise.race([
            this.arbiter.desymbolize(node.value),
            new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error()), remaining); }),
          ]);
        } finally { if (timer) clearTimeout(timer); }
        if (typeof resolved !== "string") throw new Error();
        if (resolved === node.value) continue;
        const text = JSON.stringify(resolved);
        bytes += Buffer.byteLength(text) - Buffer.byteLength(source.slice(node.start, node.end));
        if (bytes > this.maxOutputBytes) { this.diagnostic("record-limit"); return source; }
        patches.push({ node, text });
      }
    } catch { this.diagnostic("resolution-failed"); return source; }
    if (patches.length === 0) return source;
    let output = source;
    for (const { node, text } of patches.reverse()) output = output.slice(0, node.start) + text + output.slice(node.end);
    try { await this.opts.onResolve?.(source, output); } catch { /* observability only */ }
    return output;
  }
}
