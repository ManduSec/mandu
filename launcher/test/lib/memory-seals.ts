/**
 * An in-memory stand-in for the arbiter's seal ops (plan 14 §11.2), the
 * mock half of the arbiter-client pattern for `CacheSealClient`
 * (launcher/src/cache-seals.ts). It keeps the arbiter's rule: one epoch,
 * add-only seals, `honoured` false while `unconfined` is set, and
 * `rotate()` voids every seal (and records why, as the arbiter's
 * `epochCause`, plan 14 §11.2.1). The real wiring is pinned by
 * tests/stack/cache-seals-parity.test.ts.
 */
import type { CacheSealClient, CacheSealsWire, EpochCause, SealEntry, SealRejection, VoidingLaunch } from "../../src/cache-seals.js";

export interface MemorySeals extends CacheSealClient {
  seals: SealEntry[];
  rejected: SealRejection[];
  lookups: number;
  epoch: string;
  unconfined: boolean;
  /** The launches named as the reason while `unconfined` (plan 14 §11.2.1); none: an older arbiter. */
  live?: VoidingLaunch[];
  /** Why the current epoch began (answered while honoured); none: an older arbiter. */
  epochCause?: EpochCause;
  rotate(cause?: EpochCause): void;
}

export function memorySeals(): MemorySeals {
  let n = 0;
  const m: MemorySeals = {
    seals: [],
    rejected: [],
    lookups: 0,
    epoch: "e0",
    unconfined: false,
    rotate(cause) { m.seals = []; m.epoch = `e${++n}`; m.epochCause = cause; },
    async lookup(kind, keys): Promise<CacheSealsWire> {
      m.lookups++;
      if (m.unconfined) return { epoch: m.epoch, honoured: false, reason: "1 unconfined launch is live", ...(m.live ? { live: m.live } : {}), seals: [] };
      const want = new Set(keys);
      return { epoch: m.epoch, honoured: true, ...(m.epochCause !== undefined ? { epochCause: m.epochCause } : {}), seals: m.seals.filter((s) => s.kind === kind && want.has(s.key)).map((s) => ({ key: s.key, sha256: s.sha256, size: s.size })) };
    },
    async record(entries, rejected) {
      for (const e of entries) {
        if (!m.seals.some((s) => s.kind === e.kind && s.key === e.key && s.sha256 === e.sha256 && s.size === e.size)) m.seals.push({ ...e });
      }
      m.rejected.push(...rejected);
      return { epoch: m.epoch, recorded: entries.length };
    },
  };
  return m;
}
