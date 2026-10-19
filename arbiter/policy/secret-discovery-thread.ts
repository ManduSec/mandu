/**
 * secret-discovery-thread — the `discoverSecrets` walk on a worker thread
 * (docs/design/architecture/runtime-instances.md §14.2 item 7; confidentiality.md §7.2 "Discovery
 * cost is launch latency AND an arbiter freeze").
 *
 * The walk is ~1-3 s of synchronous readdir/lstat on a developer HOME. Run in
 * the arbiter's event loop it froze EVERY client for that long (the launching
 * session's own watcher and proxies, and on a shared stack every other
 * session). Here the arbiter takes a snapshot of the label stores at request
 * time (`LabelSnapshot`), and a worker runs exactly the same
 * `discoverSecretsReport` over it. The answer is what the in-process walk
 * would have returned at that instant: a label act landing during the walk is
 * seen by the next discovery, as one landing just after a synchronous walk was.
 *
 * The worker only READS the filesystem and returns plain data; it never opens
 * the symbol DB (single-writer), never mints, never decides a gate.
 *
 * Where the worker entry lives: beside this module in the source tree
 * (`secret-discovery-worker.ts`, which the worker loads after registering
 * tsx itself: `tsxBootstrap`), beside the compiled module
 * (`.js`), or beside the single-file bundle (`dist/secret-discovery-worker.mjs`,
 * bundle-manifest.json `modules`). A worker that cannot start or dies without
 * answering falls back to the same walk in-process: the old behavior, never a
 * different answer. A walk that THROWS in the worker is that error (the
 * in-process walk would throw the same). One thread serves the arbiter for
 * its lifetime (`DiscoveryWorker`).
 *
 * Mandu-new (no reference origin).
 */
import { Worker } from "node:worker_threads";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { discoverSecretsReport, type DiscoveryOptions, type SecretDiscoveryReport } from "./secret-discovery.js";
import { snapshotLookup, type LabelSnapshot } from "./label-lookup.js";

/** One discovery, as the worker receives it (structured-cloned). */
export interface DiscoveryJob {
  roots: string[];
  home?: string;
  opts: DiscoveryOptions;
  labels: LabelSnapshot;
}

export type DiscoveryWorkerReply =
  | { ok: true; report: SecretDiscoveryReport }
  | { ok: false; error: string };

/** The walk itself, as both the worker and the in-process path run it. */
export function runDiscoveryJob(job: DiscoveryJob): SecretDiscoveryReport {
  return discoverSecretsReport(job.roots, job.home, snapshotLookup(job.labels), job.opts);
}

/** The worker entry beside THIS module, in this module's own form (`.ts`
 *  under tsx, `.js` compiled, `.mjs` for the bundle), or null if it is not
 *  there. */
export function discoveryWorkerEntry(selfUrl: string = import.meta.url): URL | null {
  const ext = selfUrl.endsWith(".ts") ? ".ts" : selfUrl.endsWith(".js") ? ".js" : ".mjs";
  const url = new URL(`./secret-discovery-worker${ext}`, selfUrl);
  try {
    return existsSync(fileURLToPath(url)) ? url : null;
  } catch {
    return null;
  }
}

/** The source tree only: tsx installs its loader on the main thread alone
 *  (a worker inherits its execArgv, yet a `./x.js` import of a `.ts` file
 *  does not resolve there), so the worker registers tsx itself before it
 *  imports the `.ts` entry. Throws where tsx is not installed; the caller
 *  then walks in-process. */
function tsxBootstrap(entry: URL): string {
  const api = import.meta.resolve("tsx/esm/api");
  return `import(${JSON.stringify(api)}).then((m) => { m.register(); return import(${JSON.stringify(entry.href)}); })`;
}

export interface DiscoveryWorkerOptions {
  /** Override the worker entry (tests); null = no worker, walk in-process. */
  entry?: URL | null;
  /** Called when a walk falls back to in-process, with the reason. */
  onFallback?: (why: string) => void;
}

interface PendingWalk {
  job: DiscoveryJob;
  resolve: (r: SecretDiscoveryReport) => void;
  reject: (e: Error) => void;
}

/**
 * One long-lived discovery thread for an arbiter. Started on the first walk,
 * or ahead of it by `warm()` (the daemon does, at listen: the start is ~0.4 s
 * under tsx, and a launch's discovery is on its critical path), then kept.
 * Walks run one at a time on it, in order, as they did in-process. It holds
 * the event loop only while a walk is pending.
 */
export class DiscoveryWorker {
  private worker: Worker | null = null;
  private readonly pending = new Map<number, PendingWalk>();
  private nextId = 1;
  private stopped = false;
  private startError: string | null = null;

  constructor(private readonly o: DiscoveryWorkerOptions = {}) {}

  /** Start the thread now, so the first walk does not pay for it. */
  warm(): void {
    this.ensure();
  }

  /** Walk `job` on the thread. The job, label snapshot included, is cloned
   *  HERE, synchronously: later label acts are not in it. */
  run(job: DiscoveryJob): Promise<SecretDiscoveryReport> {
    if (this.stopped) return Promise.reject(new Error("arbiter closing: discovery stopped"));
    const w = this.ensure();
    if (!w) {
      const why = this.startError ?? "no worker entry beside the arbiter";
      return Promise.resolve().then(() => this.inProcess(job, why));
    }
    return new Promise<SecretDiscoveryReport>((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { job, resolve, reject });
      try {
        w.postMessage({ id, job });
      } catch (err) {
        this.pending.delete(id);
        try { resolve(this.inProcess(job, `job not sent: ${(err as Error).message}`)); } catch (e) { reject(e as Error); }
        return;
      }
      w.ref();
    });
  }

  /** Terminate the thread; pending walks reject (no in-process fallback). */
  stop(): void {
    this.stopped = true;
    const err = new Error("arbiter closing: discovery stopped");
    for (const p of this.pending.values()) p.reject(err);
    this.pending.clear();
    const w = this.worker;
    this.worker = null;
    void w?.terminate();
  }

  private inProcess(job: DiscoveryJob, why: string): SecretDiscoveryReport {
    this.o.onFallback?.(why);
    return runDiscoveryJob(job);
  }

  private ensure(): Worker | null {
    if (this.stopped) return null;
    if (this.worker) return this.worker;
    const entry = this.o.entry === undefined ? discoveryWorkerEntry() : this.o.entry;
    if (entry === null) return null;
    let w: Worker;
    try {
      w = entry.pathname.endsWith(".ts")
        ? new Worker(tsxBootstrap(entry), { eval: true })
        : new Worker(entry);
    } catch (err) {
      this.startError = `worker did not start: ${(err as Error).message}`;
      return null;
    }
    this.startError = null;
    w.unref();
    w.on("message", (m: { id: number; reply: DiscoveryWorkerReply }) => {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (this.pending.size === 0) w.unref();
      if (m.reply.ok) p.resolve(m.reply.report);
      else p.reject(new Error(m.reply.error));
    });
    w.once("error", (err) => this.lost(w, `worker failed: ${err.message}`));
    w.once("exit", (code) => this.lost(w, `worker exited (${code})`));
    this.worker = w;
    return w;
  }

  /** The thread is gone: every walk it held runs in-process (the old
   *  behavior, the same answer); the next walk starts a new thread. */
  private lost(w: Worker, why: string): void {
    if (this.worker === w) this.worker = null;
    const held = [...this.pending.values()];
    this.pending.clear();
    for (const p of held) {
      try { p.resolve(this.inProcess(p.job, why)); } catch (e) { p.reject(e as Error); }
    }
  }
}
