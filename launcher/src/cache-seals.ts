/**
 * cache-seals — the launcher's half of the enforcement caches' seals
 * (confidentiality-plan-14-policy-suggestions.md §11.2; the arbiter's half
 * is arbiter/policy/cache-seals.ts).
 *
 * The git-object twins keep two caches under the Mandu home: the sanitized
 * packs (`cache/object-twins/<key>/`) and the history walks
 * (`state/object-walks/<key>.json`). Either one, written by something
 * unconfined, would make a later `secrets` launch serve a secret: a pack
 * holding the real bytes under a clean `.idx`, or a walk entry with a
 * version left out. So every entry the launcher writes is SEALED with the
 * arbiter (sha256 and size, over its human socket), and every entry it reads
 * is used only when its bytes match a seal of the arbiter's CURRENT epoch;
 * anything else is rebuilt and reported (an event naming the kind and key,
 * no content). The arbiter voids every seal when an unconfined period ends.
 *
 *   kind `object-twin`   key `<pack cache key>/<file name>` (.pack/.idx/.rev)
 *   kind `history-walk`  key = the walk file's name without `.json`
 *
 * No seal client (an arbiter without a human socket, a test that passes
 * none) means no cache is trusted: every launch walks and rebuilds. A
 * lookup that fails is the same. Hashing a large pack costs about 0.65 s per
 * 500 MB (measured 2026-09-30); one launch hashes a file once, keyed by its
 * path, device, inode, size, mtime and ctime (file-hashes.ts, which hashes
 * on worker threads, in parallel and as early as the files are known; the
 * full hash, and the check still gates the use).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { FileHashes, hashFileHere, type FileHash } from "./file-hashes.js";

export const SEAL_KIND_OBJECT_TWIN = "object-twin";
export const SEAL_KIND_HISTORY_WALK = "history-walk";

/** One seal on the wire (arbiter/ipc/protocol.ts; the launcher does not
 *  import the arbiter). */
export interface SealEntry {
  kind: string;
  key: string;
  sha256: string;
  size: number;
}

export interface SealRejection {
  kind: string;
  key: string;
  reason: "unsealed" | "mismatch";
}

/** An unconfined launch that holds the seals void (the arbiter's `live`;
 *  display only, plan 14 §11.2.1). */
export interface VoidingLaunch {
  pid: number;
  mode: string;
  posture: string;
  /** Why it is unconfined, in the arbiter's words (`unconfinedWhy`). */
  why?: string;
  workspace?: string;
  session?: string;
}

/** Why the arbiter's current seal epoch began (arbiter/policy/cache-seals.ts
 *  `EpochCause`; display only). */
export type EpochCause = "unprotected-ended" | "unclean-stop" | "first-start";
const EPOCH_CAUSES: readonly string[] = ["unprotected-ended", "unclean-stop", "first-start"];

/** The arbiter's `cacheSeals` answer. */
export interface CacheSealsWire {
  epoch: string;
  honoured: boolean;
  reason?: string;
  /** The unconfined launches that are why (absent from an older arbiter). */
  live?: VoidingLaunch[];
  /** Why the current epoch began, when honoured (absent from an older
   *  arbiter; an unknown value is dropped). */
  epochCause?: EpochCause;
  seals: Array<{ key: string; sha256: string; size: number }>;
}

/** A string from the arbiter fit to print on this terminal: no control
 *  character, at most `max` characters; else undefined. */
function printable(v: unknown, max: number): string | undefined {
  // eslint-disable-next-line no-control-regex
  return typeof v === "string" && v !== "" && v.length <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(v) ? v : undefined;
}

/** The `live` list, checked: an entry not shaped right is dropped (display
 *  only; the answer's `honoured` decides, never this). */
function asVoiding(v: unknown): VoidingLaunch[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: VoidingLaunch[] = [];
  for (const o of v.slice(0, 5)) {
    if (o === null || typeof o !== "object") continue;
    const x = o as Record<string, unknown>;
    if (!Number.isSafeInteger(x.pid) || (x.pid as number) <= 0) continue;
    const why = printable(x.why, 80);
    const workspace = printable(x.workspace, 512);
    const session = printable(x.session, 128);
    out.push({
      pid: x.pid as number, mode: printable(x.mode, 40) ?? "unknown", posture: printable(x.posture, 40) ?? "unknown",
      ...(why !== undefined ? { why } : {}), ...(workspace !== undefined ? { workspace } : {}), ...(session !== undefined ? { session } : {}),
    });
  }
  return out;
}

/** The marker the voided-caches line starts with (compactNotice matches it). */
export const VOIDED_CACHES_PREFIX = "mandu: the git-history caches are not trusted this launch: ";

/** Why a launch is unconfined, as the notice says it: the arbiter's words,
 *  else what its mode and posture say. */
export function voidingWhy(l: VoidingLaunch): string {
  return l.why ?? (l.mode === "off" ? "protection off" : `mode ${l.mode}, posture ${l.posture}`);
}

/**
 * The line a launch logs when it finds the git-history caches void because
 * other launches run unconfined (plan 14 §11.2.1): each by pid, workspace
 * and why, and how to end it. The rule is unchanged (no seal is honoured
 * while any unconfined launch lives); this only says which launch costs this
 * one its cache. The compact display shows it as one `mandu: ! …` line
 * (launch-banner.ts compactNotice). Pure.
 */
export function voidedCachesLine(live: readonly VoidingLaunch[]): string {
  const named = live.slice(0, 3).map((l) =>
    `pid ${l.pid}${l.workspace !== undefined ? ` in ${l.workspace}` : ""}` +
    `${l.session !== undefined ? ` (session ${l.session})` : ""}: ${voidingWhy(l)}`);
  const more = live.length > 3 ? `; and ${live.length - 3} more` : "";
  const one = live.length === 1;
  return `${VOIDED_CACHES_PREFIX}${one ? "a Mandu launch runs" : `${live.length} Mandu launches run`} without protection ` +
    `(${named.join("; ")}${more}), and while one does nothing it could have written is trusted; ` +
    "rebuilding the sanitized git history (slower). " +
    `The caches are trusted again once ${one ? "it ends" : "they end"}: quit ${one ? "its agent" : "their agents"}, or \`kill ${live[0]!.pid}\`.`;
}

/** The tail every history re-check notice ends with (isHistoryRecheckNotice). */
const RECHECK_RE = /^mandu: ! .+, so Mandu is re-checking the git history of \d+ repositor(?:y|ies) \(slower this once\)$/;

/**
 * The ONE line a launch prints, before the work, when it must re-check the
 * git history because the caches it finds on disk carry no seal of the
 * arbiter's current epoch (plan 14 §11.2.1 "The rebuild notice"): most often
 * the first launch after an unprotected one ended (`--no-net-guard`, mode
 * `off`, a `gated` posture), which costs seconds on a large checkout and was
 * silent without `--verbose`. `repos`: the repositories (object stores) the
 * step covers. Plain words: no epoch, no seal, no pack. Pure.
 */
export function historyRecheckNotice(cause: EpochCause | undefined, repos: number): string {
  const why = cause === "unprotected-ended"
    ? "an earlier Mandu session without protection has ended"
    : cause === "unclean-stop"
      ? "Mandu's protection service restarted after an unprotected or abrupt stop"
      : "Mandu's earlier checks could not be vouched for";
  const n = Math.max(1, repos);
  return `mandu: ! ${why}, so Mandu is re-checking the git history of ${n} repositor${n === 1 ? "y" : "ies"} (slower this once)`;
}

/** Does `note` come from historyRecheckNotice? (launch-banner.ts prints it
 *  at once, in every display mode.) */
export function isHistoryRecheckNotice(note: string): boolean {
  return RECHECK_RE.test(note);
}

/** The answer, checked: a shape the launcher does not understand trusts
 *  nothing (the caller rebuilds), never "everything sealed". */
export function asCacheSeals(v: unknown): CacheSealsWire {
  const o = v as Partial<CacheSealsWire> | null;
  if (o === null || typeof o !== "object" || typeof o.epoch !== "string" || typeof o.honoured !== "boolean" || !Array.isArray(o.seals)
    || !o.seals.every((s) => s !== null && typeof s === "object" && typeof s.key === "string" && typeof s.sha256 === "string"
      && /^[0-9a-f]{64}$/.test(s.sha256) && Number.isSafeInteger(s.size))) {
    throw new Error("cacheSeals: the arbiter's answer is not {epoch, honoured, seals[]}");
  }
  const live = asVoiding((o as { live?: unknown }).live);
  return {
    epoch: o.epoch,
    honoured: o.honoured,
    ...(typeof o.reason === "string" ? { reason: o.reason } : {}),
    ...(live !== undefined && live.length > 0 ? { live } : {}),
    ...(typeof o.epochCause === "string" && EPOCH_CAUSES.includes(o.epochCause) ? { epochCause: o.epochCause } : {}),
    seals: o.seals.map((s) => ({ key: s.key, sha256: s.sha256, size: s.size })),
  };
}

/** The narrow arbiter surface (CONTRIBUTING.md arbiter-client pattern): the
 *  human-plane `cacheSeals` and `sealCacheEntries`. */
export interface CacheSealClient {
  lookup(kind: string, keys: string[]): Promise<CacheSealsWire>;
  record(entries: SealEntry[], rejected: SealRejection[]): Promise<unknown>;
}

/** sha256, size and identity of a file, streamed (file-hashes.ts
 *  hashFileWith). Throws when it cannot be read or changed while read. */
export function hashFile(path: string): FileHash {
  return hashFileHere(path);
}

export function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * One launch's use of the seals: lookups, the hash memo, and the seals and
 * rejections to report at the end (`flush`). Without a client nothing is
 * trusted.
 */
export class SealSession {
  readonly entries: SealEntry[] = [];
  readonly rejected: SealRejection[] = [];
  /** Why nothing was trusted this launch (the first reason), or null. */
  distrust: string | null = null;
  /** The unconfined launches the arbiter named as that reason (plan 14
   *  §11.2.1), or null. */
  voidedBy: VoidingLaunch[] | null = null;
  /** The launch's file hashes (shared with the caller when it passes them). */
  readonly hashes: FileHashes;
  /**
   * Called ONCE, the first time a cache entry on disk has no seal of the
   * current (honoured) epoch: the launch is about to walk and rebuild what
   * that cache held (plan 14 §11.2.1 "The rebuild notice"). Not called for
   * a mismatch (flush warns), nor while no seal is honoured (the voided
   * line says why). Display only: a throw is swallowed, and nothing it does
   * changes what is trusted.
   */
  onRecheck?: (cause: EpochCause | undefined) => void;
  private recheckSaid = false;
  /** The cause the last honoured answer gave. */
  private epochCause: EpochCause | undefined;

  /** `hash`: the launch's FileHashes (the caller closes them), or a function
   *  computing one hash (a test knob: no workers). Default: hashes of this
   *  session's own, on the main thread. */
  constructor(
    private readonly client: CacheSealClient | undefined,
    private readonly log?: (m: string) => void,
    hash?: FileHashes | ((path: string) => FileHash | Promise<FileHash>),
  ) {
    this.hashes = hash instanceof FileHashes ? hash : new FileHashes(hash !== undefined ? { hash } : { workers: 0 });
    if (client === undefined) this.distrust = "no seal service (the arbiter reported no human socket)";
  }

  get enabled(): boolean {
    return this.client !== undefined;
  }

  /** The current epoch's seals for these keys, or null when nothing may be
   *  trusted now (no client, not honoured, a failed or malformed answer). */
  private async lookup(kind: string, keys: string[]): Promise<Map<string, Array<{ sha256: string; size: number }>> | null> {
    if (this.client === undefined) return null;
    let got: CacheSealsWire;
    try {
      got = asCacheSeals(await this.client.lookup(kind, keys));
    } catch (e) {
      this.noteDistrust(`the seal lookup failed: ${(e as Error).message}`);
      return null;
    }
    if (!got.honoured) {
      this.noteDistrust(got.reason ?? "the arbiter honours no seal now", got.live);
      return null;
    }
    this.epochCause = got.epochCause;
    const m = new Map<string, Array<{ sha256: string; size: number }>>();
    for (const s of got.seals) {
      const l = m.get(s.key) ?? [];
      l.push({ sha256: s.sha256, size: s.size });
      m.set(s.key, l);
    }
    return m;
  }

  private noteDistrust(why: string, live?: VoidingLaunch[]): void {
    if (this.distrust !== null) return;
    this.distrust = why;
    if (live !== undefined && live.length > 0) {
      this.voidedBy = live;
      this.log?.(voidedCachesLine(live));
      return;
    }
    this.log?.(`mandu: the git-history caches are not trusted this launch (${why}); rebuilding what they hold`);
  }

  /** Are these bytes (read from a cache entry) vouched for by a seal of the
   *  current epoch? A refusal is recorded; a pass refreshes the seal. */
  async verifyBytes(kind: string, key: string, bytes: Buffer): Promise<boolean> {
    const seals = await this.lookup(kind, [key]);
    if (seals === null) return false;
    const sha = sha256Hex(bytes);
    return this.judge(kind, key, seals.get(key), { sha256: sha, size: bytes.length });
  }

  /** Are these files (one cache entry's parts) each vouched for? All or
   *  nothing: one refusal refuses the entry. The files hash while the seal
   *  lookup is asked, each in full; every one is judged before the answer. */
  async verifyFiles(kind: string, items: ReadonlyArray<{ key: string; path: string }>): Promise<boolean> {
    if (items.length === 0) return false;
    if (this.client !== undefined) this.hashes.prefetch(items.map((i) => i.path));
    const seals = await this.lookup(kind, items.map((i) => i.key));
    if (seals === null) return false;
    const got = await Promise.all(items.map((it) => this.hashes.current(it.path).then((h) => h, () => null)));
    let ok = true;
    items.forEach((it, i) => {
      const h = got[i];
      if (h === null || h === undefined) { ok = false; return; }
      if (!this.judge(kind, it.key, seals.get(it.key), h)) ok = false;
    });
    return ok;
  }

  /** Start hashing files a verifyFiles will ask about (a no-op without a
   *  seal client: nothing cached is trusted then). */
  prefetch(paths: Iterable<string>): void {
    if (this.client !== undefined) this.hashes.prefetch(paths);
  }

  private judge(kind: string, key: string, seals: Array<{ sha256: string; size: number }> | undefined, h: { sha256: string; size: number }): boolean {
    if (seals === undefined || seals.length === 0) {
      this.rejected.push({ kind, key, reason: "unsealed" });
      this.noteRecheck();
      return false;
    }
    if (!seals.some((s) => s.sha256 === h.sha256 && s.size === h.size)) {
      this.rejected.push({ kind, key, reason: "mismatch" });
      return false;
    }
    this.entries.push({ kind, key, sha256: h.sha256, size: h.size });
    return true;
  }

  private noteRecheck(): void {
    if (this.recheckSaid || this.onRecheck === undefined) return;
    this.recheckSaid = true;
    try { this.onRecheck(this.epochCause); } catch { /* display only */ }
  }

  /** Seal bytes just written. */
  sealBytes(kind: string, key: string, bytes: Buffer): void {
    if (this.client === undefined) return;
    this.entries.push({ kind, key, sha256: sha256Hex(bytes), size: bytes.length });
  }

  /** Seal a file just written. A file that cannot be hashed is not sealed
   *  (the next launch rebuilds it). */
  async sealFile(kind: string, key: string, path: string): Promise<void> {
    if (this.client === undefined) return;
    try {
      const h = await this.hashes.current(path);
      this.entries.push({ kind, key, sha256: h.sha256, size: h.size });
    } catch { /* unsealed: rebuilt next time */ }
  }

  /** Report the seals and the rejections to the arbiter. Never throws: a
   *  seal that is not recorded costs a rebuild next launch. */
  async flush(): Promise<void> {
    if (this.client === undefined || (this.entries.length === 0 && this.rejected.length === 0)) return;
    const mismatched = this.rejected.filter((r) => r.reason === "mismatch");
    if (mismatched.length > 0) {
      this.log?.(
        `WARNING: mandu: ${mismatched.length} git-history cache entr${mismatched.length === 1 ? "y" : "ies"} did not match its seal and ` +
        `${mismatched.length === 1 ? "was" : "were"} rebuilt (${mismatched.slice(0, 3).map((r) => `${r.kind} ${r.key}`).join(", ")}${mismatched.length > 3 ? ", …" : ""}); ` +
        "something outside Mandu's protection wrote to Mandu's cache",
      );
    }
    try {
      // Unique entries (a file verified twice is sealed once).
      const seen = new Set<string>();
      const entries = this.entries.filter((e) => { const k = `${e.kind}\0${e.key}\0${e.sha256}\0${e.size}`; if (seen.has(k)) return false; seen.add(k); return true; });
      for (let i = 0; i < Math.max(entries.length, 1); i += 5000) {
        await this.client.record(entries.slice(i, i + 5000), i === 0 ? this.rejected.slice(0, 5000) : []);
      }
    } catch (e) {
      this.log?.(`mandu: could not record the git-history cache seals (${(e as Error).message}); the next launch rebuilds them`);
    }
  }
}
