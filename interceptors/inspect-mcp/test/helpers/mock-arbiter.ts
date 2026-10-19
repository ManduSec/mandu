/**
 * mock-arbiter — an in-memory Arbiter for the inspect-mcp test suite.
 *
 * Mandu M4 (interceptors/inspect-mcp) test helper. Implements the same narrow
 * `Arbiter` interface the inspect_symbol core depends on (src/arbiter-client.ts)
 * WITHOUT the real arbiter daemon, so the suite never depends on the arbiter — nor
 * on the `emit` op the arbiter sub-agent is adding in parallel — actually landing.
 *
 * Behavior mirrors the arbiter's real contract closely enough to exercise the
 * core's logic:
 *   - resolve:   returns a value seeded via `seed()`, else null (unknown symbol).
 *   - symbolize: allocates a $MDU:<tool>[<hash>] token (the arbiter's
 *                symbol-format shape) and records value→symbol so tests can
 *                assert the raw value never leaks and the result IS a symbol.
 *   - emit:      records the event and returns a monotonic { seq }.
 *   - modelEndpoints (Plan 11 D5): the declared endpoints set via
 *                `declareEndpoints()` (the op is DEFINED only then, so a
 *                default instance behaves like an arbiter predating it).
 *   - resolve at an endpoint (Plan 11 D4): a `$MDU:localmodel_` symbol
 *                resolves ONLY when `opts.endpoint` names a declared
 *                `local: true` endpoint; otherwise null, as the arbiter
 *                refuses it. Every call's options are recorded.
 *
 * Failure injection: set `failResolve` / `failSymbolize` / `failEmit` to make
 * those ops throw, so tests can assert the core's FAIL-CLOSED path. Set
 * `symbolizeReturnsRaw` to make symbolize misbehave (return non-symbol) so the
 * core's "did not yield an opaque symbol" guard is exercised.
 */

import { createHash } from "node:crypto";
import type {
  Arbiter,
  ModelEndpoint,
  ResolveOptions,
  SymbolizeArgs,
  SymbolProvenance,
} from "../../src/arbiter-client.js";
import type { ManduEvent } from "../../src/event-model.js";

export interface MockArbiterOptions {
  failResolve?: boolean;
  failSymbolize?: boolean;
  failEmit?: boolean;
  /** Make symbolize return a NON-symbol string (misbehaving arbiter). */
  symbolizeReturnsRaw?: boolean;
  /** Make the OPTIONAL provenance op throw (transient arbiter failure) —
   *  the core must degrade to provenance-free triage, never refuse. */
  failProvenance?: boolean;
  /** Make the modelEndpoints op (once declared) throw. */
  failModelEndpoints?: boolean;
}

export class MockArbiter implements Arbiter {
  /** symbol → raw value, seeded by tests (the table the arbiter owns). */
  readonly table = new Map<string, string>();
  /** Every resolve call, for assertions. */
  readonly resolveCalls: string[] = [];
  /** Every resolve call WITH its options (Plan 11: the endpoint name). */
  readonly resolveRequests: Array<{ symbol: string; opts?: ResolveOptions }> = [];
  /** How many times modelEndpoints was asked. */
  modelEndpointsCalls = 0;
  private endpoints: ModelEndpoint[] = [];
  /** Every symbolize call, for assertions. */
  readonly symbolizeCalls: SymbolizeArgs[] = [];
  /** Every emitted event, for assertions. */
  readonly emitted: ManduEvent[] = [];
  /** value → minted symbol, so re-symbolization is stable per value. */
  private readonly symbolOf = new Map<string, string>();
  private seq = 0;

  constructor(private readonly opts: MockArbiterOptions = {}) {}

  /** Seed a known symbol → raw value (an existing untrusted span). */
  seed(symbol: string, value: string): this {
    this.table.set(symbol, value);
    return this;
  }

  async resolve(symbol: string, opts?: ResolveOptions): Promise<string | null> {
    this.resolveCalls.push(symbol);
    this.resolveRequests.push(opts === undefined ? { symbol } : { symbol, opts });
    if (this.opts.failResolve) throw new Error("mock arbiter: resolve failure (injected)");
    if (symbol.startsWith("$MDU:localmodel_")) {
      // The arbiter's admits(location, level): local-model only at a local
      // endpoint from ITS OWN registry; undeclared or absent ⇒ external.
      const ep = opts?.endpoint;
      const local = ep !== undefined && this.endpoints.some((e) => e.name === ep && e.local === true);
      if (!local) return null;
    }
    return this.table.has(symbol) ? this.table.get(symbol)! : null;
  }

  /** Declare policy.yaml `models:` AND enable the modelEndpoints op. */
  declareEndpoints(endpoints: ModelEndpoint[]): this {
    this.endpoints = endpoints;
    if (!this.modelEndpoints) {
      this.modelEndpoints = async (): Promise<ModelEndpoint[]> => {
        this.modelEndpointsCalls++;
        if (this.opts.failModelEndpoints) throw new Error("mock arbiter: modelEndpoints failure (injected)");
        return this.endpoints.map((e) => ({ ...e }));
      };
    }
    return this;
  }

  /** OPTIONAL per the Arbiter interface; assigned by declareEndpoints(). */
  modelEndpoints?: () => Promise<ModelEndpoint[]>;

  async symbolize(args: SymbolizeArgs): Promise<string> {
    this.symbolizeCalls.push(args);
    if (this.opts.failSymbolize) throw new Error("mock arbiter: symbolize failure (injected)");
    if (this.opts.symbolizeReturnsRaw) {
      // Misbehaving arbiter: echoes the raw value back instead of a symbol.
      return args.value;
    }
    const key = JSON.stringify([args.tool, args.value]);
    const existing = this.symbolOf.get(key);
    if (existing) return existing;
    const hash = createHash("sha256").update(key).digest("hex").slice(0, 4);
    const symbol = `$MDU:${sanitizeTool(args.tool)}[${hash}]`;
    this.symbolOf.set(key, symbol);
    this.table.set(symbol, args.value);
    return symbol;
  }

  async emit(event: ManduEvent): Promise<{ seq: number }> {
    if (this.opts.failEmit) throw new Error("mock arbiter: emit failure (injected)");
    const seq = ++this.seq;
    this.emitted.push({ ...event, seq });
    return { seq };
  }

  /** symbol → provenance, seeded by tests. The `provenance` method is only
   *  DEFINED once something is seeded (or failProvenance is set), so default
   *  MockArbiter instances exercise the no-op degradation path exactly like
   *  an older arbiter build. */
  private readonly provenanceOf = new Map<string, SymbolProvenance>();

  /** Seed the §4.1 v2 provenance for a symbol AND enable the optional op. */
  seedProvenance(symbol: string, p: SymbolProvenance): this {
    this.provenanceOf.set(symbol, p);
    this.enableProvenance();
    return this;
  }

  /** Enable the optional provenance op without seeding (or with failure
   *  injection): unseeded symbols answer all-nulls like the real arbiter. */
  enableProvenance(): this {
    if (!this.provenance) {
      this.provenance = async (symbol: string): Promise<SymbolProvenance> => {
        if (this.opts.failProvenance) {
          throw new Error("mock arbiter: provenance failure (injected)");
        }
        return this.provenanceOf.get(symbol) ?? { tool: null, callId: null, toolName: null };
      };
    }
    return this;
  }

  /** OPTIONAL per the Arbiter interface — assigned by enableProvenance(). */
  provenance?: (symbol: string) => Promise<SymbolProvenance>;
}

/** Mirror the arbiter symbol-format shortToolTag (short + grammar-safe tag). */
function sanitizeTool(tool: string): string {
  let tag = tool.startsWith("mcp__") ? tool.split("__").filter(Boolean).pop() ?? tool : tool;
  tag = tag.replace(/[^a-zA-Z0-9_]/g, "_");
  if (!/^[a-zA-Z_]/.test(tag)) tag = `t_${tag}`;
  if (tag === "inspect_symbol") tag = "inspect";
  if (tag.length > 24) tag = tag.slice(0, 24).replace(/_+$/, "") || "tool";
  return tag;
}
