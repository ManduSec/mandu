/**
 * file-hashes — the seal check's file hashes, computed off the main thread
 * and ahead of need (confidentiality-plan-14-policy-suggestions.md §11.2,
 * "The check's cost"; confidentiality.md §7.2a "Cost on a relaunch").
 *
 * A cached sanitized pack is served only when the sha256 of every file the
 * twin uses matches a seal of the arbiter's current epoch (cache-seals.ts).
 * The hash is the full hash of the whole file, always; what this module
 * changes is only WHEN and WHERE it is computed:
 *
 *   - on worker threads (up to four), so the packs of one launch hash in
 *     parallel and beside the git calls the twins make, not one after the
 *     other on the main thread after them;
 *   - started early (`prefetch`): as soon as the files are known, before the
 *     seal lookup answers, or (twin-prefetch.ts) at launch start for the
 *     packs the last launch used.
 *
 * A hash computed early is used only for the file it was computed from: each
 * result carries the file's identity (device, inode, size, mtime and ctime
 * in nanoseconds) as fstat saw it BEFORE and AFTER the read (they must be
 * equal, or the hash is refused), and `current` stats the path again when
 * the hash is asked for and recomputes it on any difference. A file is never
 * vouched for by a hash of other bytes than its own; the check still
 * completes, and gates, before the twin is served.
 *
 * Workers are an accelerator only: a worker that cannot start, dies, or
 * answers something unreadable hands its jobs to the main thread (the same
 * function, `hashFileWith`), never a failed or skipped check.
 * MANDU_HASH_WORKERS=0 hashes on the main thread.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";

/** One file's full sha256 and the identity of the file it was read from. */
export interface FileHash {
  sha256: string;
  size: number;
  dev: string;
  ino: string;
  mtimeNs: string;
  ctimeNs: string;
}

/**
 * The sha256 of the regular file at `path`, streamed, with the file's
 * identity; throws when it is not a regular file, cannot be read, or changed
 * while it was read (fstat before and after differ, or the bytes read are
 * not its size). SELF-CONTAINED (its modules are parameters, it uses no
 * other name but globals): the worker runs its source text.
 */
export function hashFileWith(nodeFs: typeof fs, nodeCrypto: typeof crypto, path: string): FileHash {
  const fd = nodeFs.openSync(path, nodeFs.constants.O_RDONLY | nodeFs.constants.O_NONBLOCK);
  try {
    const before = nodeFs.fstatSync(fd, { bigint: true });
    if (!before.isFile()) throw new Error(`${path} is not a regular file`);
    const h = nodeCrypto.createHash("sha256");
    const buf = Buffer.allocUnsafe(4 * 1024 * 1024);
    let size = 0;
    for (;;) {
      const n = nodeFs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      h.update(buf.subarray(0, n));
      size += n;
    }
    const after = nodeFs.fstatSync(fd, { bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs || BigInt(size) !== after.size) {
      throw new Error(`${path} changed while it was hashed`);
    }
    return {
      sha256: h.digest("hex"), size,
      dev: String(after.dev), ino: String(after.ino), mtimeNs: String(after.mtimeNs), ctimeNs: String(after.ctimeNs),
    };
  } finally {
    nodeFs.closeSync(fd);
  }
}

/** hashFileWith on this thread. */
export function hashFileHere(path: string): FileHash {
  return hashFileWith(fs, crypto, path);
}

/** Is `h` a hash of the file `st` describes now (same device, inode, size,
 *  mtime and ctime)? Pure. */
export function sameFile(h: FileHash, st: fs.BigIntStats): boolean {
  return h.dev === String(st.dev) && h.ino === String(st.ino) && BigInt(h.size) === st.size
    && h.mtimeNs === String(st.mtimeNs) && h.ctimeNs === String(st.ctimeNs);
}

/** How many hash workers (MANDU_HASH_WORKERS; default up to 4, one fewer
 *  than the CPUs, at least 1; 0 = the main thread). Pure. */
export function hashWorkersFromEnv(env: Record<string, string | undefined>, cpus: number = availableParallelism()): number {
  const v = env["MANDU_HASH_WORKERS"];
  if (v !== undefined && v.trim() !== "") {
    const n = Number(v);
    if (Number.isInteger(n) && n >= 0) return Math.min(n, 16);
  }
  return Math.max(1, Math.min(4, cpus - 1));
}

const WORKER_SOURCE = `"use strict";
const { parentPort } = require("node:worker_threads");
const fs = require("node:fs");
const crypto = require("node:crypto");
const hashFileWith = ${hashFileWith.toString()};
parentPort.on("message", (m) => {
  let reply;
  try { reply = { id: m.id, ok: true, v: hashFileWith(fs, crypto, m.path) }; }
  catch (e) { reply = { id: m.id, ok: false, error: String((e && e.message) || e) }; }
  parentPort.postMessage(reply);
});
`;

interface Job { path: string; resolve: (h: FileHash) => void; reject: (e: Error) => void }

/** A worker's answer, checked: anything else is the worker's failure. */
function asFileHash(v: unknown): FileHash | null {
  const o = v as Partial<FileHash> | null;
  if (o === null || typeof o !== "object" || typeof o.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(o.sha256)
    || !Number.isSafeInteger(o.size) || [o.dev, o.ino, o.mtimeNs, o.ctimeNs].some((x) => typeof x !== "string" || !/^[0-9]+$/.test(x))) return null;
  return { sha256: o.sha256, size: o.size!, dev: o.dev!, ino: o.ino!, mtimeNs: o.mtimeNs!, ctimeNs: o.ctimeNs! };
}

/** A small pool of hash workers. A worker is referenced only while it has a
 *  job, so an idle pool never holds the process open. */
class HashWorkerPool {
  private readonly workers: Array<{ w: Worker; jobs: Map<number, Job> }> = [];
  private seq = 0;
  private broken = false;
  private closed = false;
  /** Files hashed on the main thread because no worker could (a test and
   *  log aid). */
  fellBack = 0;

  private here(path: string): FileHash {
    this.fellBack++;
    return this.fallback(path);
  }

  constructor(private readonly size: number, private readonly fallback: (path: string) => FileHash, private readonly source: string = WORKER_SOURCE) {}

  run(path: string): Promise<FileHash> {
    if (this.closed) return Promise.reject(new Error("the hash pool is closed"));
    if (this.broken) return Promise.resolve().then(() => this.here(path));
    return new Promise<FileHash>((resolve, reject) => {
      const slot = this.pick();
      if (slot === null) { this.broken = true; resolve(Promise.resolve().then(() => this.here(path))); return; }
      const id = ++this.seq;
      slot.jobs.set(id, { path, resolve, reject });
      if (slot.jobs.size === 1) slot.w.ref();
      slot.w.postMessage({ id, path });
    });
  }

  /** The least busy worker: an idle one, else a new one while under the
   *  size, else the one with fewest jobs; null when none can be started. */
  private pick(): { w: Worker; jobs: Map<number, Job> } | null {
    const idle = this.workers.find((s) => s.jobs.size === 0);
    if (idle !== undefined) return idle;
    if (this.workers.length < this.size) {
      const s = this.spawn();
      if (s !== null) return s;
    }
    return this.workers.length === 0 ? null : this.workers.reduce((a, b) => (b.jobs.size < a.jobs.size ? b : a));
  }

  /** Start every worker now (they take tens of milliseconds to come up), so
   *  the first hashes do not wait for them. */
  warm(): void {
    while (!this.closed && !this.broken && this.workers.length < this.size) {
      if (this.spawn() === null) break;
    }
  }

  private spawn(): { w: Worker; jobs: Map<number, Job> } | null {
    let w: Worker;
    try { w = new Worker(this.source, { eval: true }); } catch { return null; }
    const slot = { w, jobs: new Map<number, Job>() };
    w.unref();
    w.on("message", (m: { id?: unknown; ok?: unknown; v?: unknown; error?: unknown } | null) => {
      const job = typeof m?.id === "number" ? slot.jobs.get(m.id) : undefined;
      if (job === undefined) return;
      slot.jobs.delete(m!.id as number);
      if (slot.jobs.size === 0) slot.w.unref();
      if (m!.ok === true) {
        const h = asFileHash(m!.v);
        if (h !== null) job.resolve(h);
        else this.handOver(job);
      } else {
        job.reject(new Error(typeof m!.error === "string" ? m!.error : "the file could not be hashed"));
      }
    });
    const lost = (): void => {
      const i = this.workers.indexOf(slot);
      if (i >= 0) this.workers.splice(i, 1);
      const jobs = [...slot.jobs.values()];
      slot.jobs.clear();
      if (!this.closed) this.broken = true;
      for (const j of jobs) this.handOver(j);
    };
    w.on("error", lost);
    w.on("exit", lost);
    this.workers.push(slot);
    return slot;
  }

  /** A job whose worker failed: the main thread hashes it (after a close,
   *  nobody waits for it: refused). */
  private handOver(j: Job): void {
    if (this.closed) { j.reject(new Error("the hash pool is closed")); return; }
    Promise.resolve().then(() => this.here(j.path)).then(j.resolve, j.reject);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const s of this.workers.splice(0)) {
      for (const j of s.jobs.values()) j.reject(new Error("the hash pool is closed"));
      s.jobs.clear();
      void s.w.terminate().catch(() => undefined);
    }
  }
}

/**
 * One launch's file hashes: each path hashed once while it stays the same
 * file, started as early as the caller can name it, answered for the file as
 * it is when asked (`current`). Close it when the launch's checks are done:
 * the workers end, and a hash still running is dropped.
 */
export class FileHashes {
  private readonly memo = new Map<string, Promise<FileHash>>();
  private readonly fresh: (path: string) => Promise<FileHash>;
  private readonly pool: HashWorkerPool | null = null;

  /** `hash`: compute a hash here instead (a test knob; no workers).
   *  `workers`: the pool size (0: the main thread; default
   *  hashWorkersFromEnv). `workerSource`: what a worker runs (a test knob:
   *  a worker that dies or answers junk). */
  constructor(opts: { hash?: (path: string) => FileHash | Promise<FileHash>; workers?: number; workerSource?: string } = {}) {
    if (opts.hash !== undefined) {
      const h = opts.hash;
      this.fresh = (p) => { try { return Promise.resolve(h(p)); } catch (e) { return Promise.reject(e as Error); } };
      return;
    }
    const n = opts.workers ?? hashWorkersFromEnv(process.env);
    if (n > 0) {
      const pool = new HashWorkerPool(n, hashFileHere, opts.workerSource);
      this.pool = pool;
      this.fresh = (p) => pool.run(p);
    } else {
      this.fresh = (p) => Promise.resolve().then(() => hashFileHere(p));
    }
  }

  private start(path: string): Promise<FileHash> {
    const p = this.fresh(path);
    p.catch(() => undefined);
    this.memo.set(path, p);
    return p;
  }

  /** Start hashing these files now (each once); `current` answers from it. */
  prefetch(paths: Iterable<string>): void {
    for (const p of paths) if (!this.memo.has(p)) this.start(p);
  }

  /** The hash of the file at `path` as it is NOW: an earlier hash only when
   *  the path still names the same file, unchanged; otherwise hashed again.
   *  Throws when it cannot be read. */
  async current(path: string): Promise<FileHash> {
    const st = fs.statSync(path, { bigint: true });
    const earlier = this.memo.get(path);
    if (earlier !== undefined) {
      const h = await earlier.catch(() => null);
      if (h !== null && sameFile(h, st)) return h;
    }
    return this.start(path);
  }

  /** Files a worker could not hash and the main thread did. */
  get fellBack(): number {
    return this.pool?.fellBack ?? 0;
  }

  /** Bring the hash workers up now (no-op without workers). */
  warm(): void {
    this.pool?.warm();
  }

  close(): void {
    this.pool?.close();
  }
}
