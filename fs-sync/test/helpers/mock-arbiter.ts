/**
 * mock-arbiter — an in-memory SymbolArbiter for the fs-sync test suite.
 *
 * Mirrors interceptors/anthropic-proxy/test/helpers/mock-arbiter.ts: implements the
 * same narrow interface the production code depends on (src/arbiter-client.ts
 * `SymbolArbiter`) WITHOUT the real arbiter daemon, so the suite never depends on
 * the arbiter process or the symbol DB.
 *
 * Behaviour mirrors the arbiter's real contract:
 *   - symbolize: allocates a stable `$MDU:<tool>[<hash>][.field]` token
 *     per (tool, value, field) and records value<->symbol so tests round-trip
 *     and assert the raw value never leaks into the AgentView.
 *   - desymbolize: replaces every KNOWN symbol in text with its raw value
 *     (unknown/obsoleted symbols are left intact — matches the arbiter).
 *   - resolve: symbol -> raw value, or null if unknown/obsoleted.
 *
 * Failure injection: set `failSymbolize` to make symbolize throw, so tests can
 * assert fs-sync's FAIL-CLOSED behaviour (a read aborts rather than leaking).
 */

import { createHash } from "node:crypto";
import type { SymbolArbiter, SymbolizeArgs } from "../../src/arbiter-client.js";

export interface MockArbiterOptions {
  failSymbolize?: boolean;
  failFileTrust?: boolean;
  /** Make emit throw — proves birth emission is BEST-EFFORT (never fails a mint). */
  failEmit?: boolean;
  /** Omit the optional emit capability entirely (an older arbiter surface). */
  noEmit?: boolean;
  /** Make pathLevel throw (an IPC error) — the guard must re-seed. */
  noPathLevel?: boolean;
  /** Delete the method entirely — an arbiter predating `pathLevel`. */
  noPathLevelOp?: boolean;
}

export class MockArbiter implements SymbolArbiter {
  /** symbol -> raw value (the table the arbiter owns; here for assertions). */
  readonly valueOf = new Map<string, string>();
  /** key(tool,value,field) -> symbol, so a value is symbolized stably. */
  private readonly symbolOf = new Map<string, string>();
  readonly symbolizeCalls: SymbolizeArgs[] = [];
  /** Symbols marked obsoleted (resolve returns null). For human-edit assertions. */
  readonly obsoleted = new Set<string>();
  /** Monotonic counter so distinct values get distinct hashes deterministically. */
  private counter = 0;
  /** Paths marked untrusted-by-origin (simulates a tainted-writer file). */
  private readonly taintedPaths = new Set<string>();
  /** Content-hashes marked untrusted-by-origin. */
  private readonly taintedHashes = new Set<string>();

  constructor(private readonly opts: MockArbiterOptions = {}) {
    // An own `undefined` shadows the prototype method, so callers observe
    // `arbiter.emit === undefined` — the optional-capability-absent shape.
    if (opts.noEmit) (this as { emit?: unknown }).emit = undefined;
    if (opts.noPathLevelOp) (this as { pathLevel?: unknown }).pathLevel = undefined;
  }

  async symbolize(args: SymbolizeArgs): Promise<string> {
    this.symbolizeCalls.push(args);
    if (this.opts.failSymbolize) throw new Error("mock arbiter: symbolize failure (injected)");

    // The real reuse key includes the SESSION (symbol-table.ts
    // findReusableSymbol), so a re-seed on a later launch mints a fresh row at
    // the currently derived level. The mock has no sessions; it models that by
    // keying a non-public level separately (public keeps the historic key, so
    // `symbolFor` and every label-free test are unchanged).
    const mintLevel = this.levelFor(args.origin);
    const key = MockArbiter.symKey(args.tool, args.value, args.field) + (mintLevel === "public" ? "" : `#${mintLevel}`);
    const existing = this.symbolOf.get(key);
    if (existing) return existing;

    // Stable, collision-resistant hash seeded by the key + a monotonic counter
    // (two different values never collide within a run).
    const hash = createHash("sha256")
      .update(`${key}#${this.counter++}`)
      .digest("hex")
      .slice(0, 4);
    const tool = sanitizeTool(args.tool);
    // The real arbiter marks the name by the level it mints (`nomodel_` strict,
    // `anymodel_` model-ok): mirror it from the mock's path labels so the
    // relabel guard has a marker to compare.
    const lvl = this.levelFor(args.origin);
    const marker = lvl === "no-model" ? "nomodel_" : lvl === "local-model" ? "localmodel_" : lvl === "any-model" ? "anymodel_" : "";
    const base = `$MDU:${marker}${tool}[${hash}]`;
    // The field suffix is encoded the way the real arbiter's
    // `canonicalSymbolField` does (arbiter/symbol-table/symbol-format.ts):
    // a path like `notes/a.md` or `.env` would otherwise not survive the
    // symbol scanner, and every re-launch fast-path check would miss it.
    const symbol = args.field ? `${base}.${canonicalField(args.field)}` : base;

    this.symbolOf.set(key, symbol);
    this.valueOf.set(symbol, args.value);
    return symbol;
  }

  async desymbolize(text: string): Promise<string> {
    // Replace every known, non-obsoleted symbol with its raw value. Longest
    // symbols first so a field-qualified name is replaced before its base.
    const known = [...this.valueOf.keys()]
      .filter((s) => !this.obsoleted.has(s))
      .sort((a, b) => b.length - a.length);
    let out = text;
    for (const sym of known) {
      out = out.split(sym).join(this.valueOf.get(sym)!);
    }
    return out;
  }

  async resolve(symbol: string): Promise<string | null> {
    if (this.obsoleted.has(symbol)) return null;
    return this.valueOf.get(symbol) ?? null;
  }

  async symbolProvenance(symbol: string): Promise<{ field?: string | null }> {
    const args = this.symbolizeCalls.find((call) => this.symbolFor(call.tool, call.value, call.field) === symbol);
    return args ? { field: args.field ?? null } : {};
  }

  async fileTrust(args: { contentHash?: string; path?: string }): Promise<{ untrusted: boolean; origin?: string }> {
    if (this.opts.failFileTrust) throw new Error("mock arbiter: fileTrust failure (injected)");
    const hit =
      (args.path !== undefined && this.taintedPaths.has(args.path)) ||
      (args.contentHash !== undefined && this.taintedHashes.has(args.contentHash));
    if (hit) return { untrusted: true, origin: "example.test" };
    return { untrusted: false };
  }

  /** Captured birth events (symbol-lineage.md G1). */
  readonly emitted: object[] = [];
  private emitSeq = 0;

  /** Optional observability channel (SymbolArbiter.emit). Constructed with
   *  `noEmit` the property is deleted so `arbiter.emit === undefined`,
   *  matching an older arbiter surface. */
  async emit(event: object): Promise<number> {
    if (this.opts.failEmit) throw new Error("mock arbiter: emit failure (injected)");
    this.emitted.push(event);
    return ++this.emitSeq;
  }

  /** Path labels (a mock of the arbiter's user-label store + catalog):
   *  longest-prefix wins. `setLabel(path, level)` to relabel; `axis` mirrors
   *  the confidentiality kill switch. */
  readonly labels = new Map<string, string>();
  axis = true;
  setLabel(path: string, level: "no-model" | "local-model" | "any-model" | "public"): void {
    this.labels.set(path, level);
  }
  levelFor(origin: string | undefined): string {
    if (!origin) return "public";
    let best: [string, string] | undefined;
    for (const [p, l] of this.labels) {
      if ((origin === p || origin.startsWith(p + "/")) && (!best || p.length > best[0].length)) best = [p, l];
    }
    return best ? best[1] : "public";
  }
  async pathLevel(path: string): Promise<{ level: string; axis: boolean }> {
    if (this.opts.noPathLevel) throw new Error("mock arbiter: pathLevel unavailable (injected)");
    return { level: this.axis ? this.levelFor(path) : "public", axis: this.axis };
  }
  /** Test helper: mark a path untrusted-by-origin (a tainted-writer wrote it). */
  taintPath(path: string): void {
    this.taintedPaths.add(path);
  }

  /** Test helper: mark a content-hash untrusted-by-origin. */
  taintHash(hash: string): void {
    this.taintedHashes.add(hash);
  }

  /** Test helper: the symbol minted for (tool, value, field), or undefined. */
  symbolFor(tool: string, value: string, field?: string): string | undefined {
    return this.symbolOf.get(MockArbiter.symKey(tool, value, field));
  }

  /** Test helper: mark a symbol obsoleted (simulates arbiter-side obsolescence). */
  obsolete(symbol: string): void {
    this.obsoleted.add(symbol);
  }

  static symKey(tool: string, value: string, field?: string): string {
    return JSON.stringify([tool, value, field ?? null]);
  }
}

/** MIRROR of arbiter/symbol-table/symbol-format.ts `canonicalSymbolField`. */
function canonicalField(field: string): string {
  const PREFIX = "__mdu_field_";
  if (/^[a-zA-Z_]/.test(field) && !/[^a-zA-Z0-9_[\].]/.test(field) && !field.startsWith(PREFIX)) return field;
  const units: string[] = [];
  for (let i = 0; i < field.length; i++) units.push(field.charCodeAt(i).toString(16).padStart(4, "0"));
  return PREFIX + units.join("");
}

function sanitizeTool(tool: string): string {
  let tag = tool.startsWith("mcp__") ? tool.split("__").filter(Boolean).pop() ?? tool : tool;
  tag = tag.replace(/[^a-zA-Z0-9_]/g, "_");
  if (!/^[a-zA-Z_]/.test(tag)) tag = `t_${tag}`;
  if (tag === "inspect_symbol") tag = "inspect";
  if (tag.length > 24) tag = tag.slice(0, 24).replace(/_+$/, "") || "tool";
  return tag;
}
