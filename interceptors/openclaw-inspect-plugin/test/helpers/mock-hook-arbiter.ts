/**
 * mock-hook-arbiter — an in-test HookArbiter (src/hook-arbiter.ts).
 *
 * The tripwire answers from a table of secret values: a surface that contains
 * one trips with that value's placeholder, unless the destination is listed
 * as bound for it. It records every scan and emit, can be told to throw or
 * hang, and never sees a socket.
 */
import type { FingerprintScanResult, FingerprintSurface, HookArbiter } from "../../src/hook-arbiter.js";

export interface MockSecret {
  symbol: string;
  value: string;
  level?: string;
  boundTo?: string[];
}

export class MockHookArbiter implements HookArbiter {
  readonly scans: Array<{ surfaces: FingerprintSurface[]; destination: string; scope?: "reply" }> = [];
  readonly events: unknown[] = [];
  failScan: Error | null = null;
  hangScan = false;
  failEmit = false;

  constructor(private readonly secrets: MockSecret[] = []) {}

  async egressFingerprintScan(surfaces: FingerprintSurface[], destination: string, scope?: "reply"): Promise<FingerprintScanResult> {
    this.scans.push({ surfaces, destination, ...(scope ? { scope } : {}) });
    if (this.hangScan) return new Promise<FingerprintScanResult>(() => {});
    if (this.failScan) throw this.failScan;
    const hits: FingerprintScanResult["hits"] = [];
    for (const s of surfaces) {
      for (const sec of this.secrets) {
        if (sec.boundTo?.includes(destination)) continue;
        if (s.text.includes(sec.value)) hits.push({ symbol: sec.symbol, level: sec.level ?? "secret", where: s.where });
      }
    }
    return { tripped: hits.length > 0, hits };
  }

  async emit(event: unknown): Promise<number> {
    if (this.failEmit) throw new Error("emit refused");
    this.events.push(event);
    return this.events.length;
  }
}
