/**
 * secret-discovery-worker — the worker-thread entry of the `discoverSecrets`
 * walk (secret-discovery-thread.ts). Answers each `{ id, job }` it is sent
 * with `{ id, reply }`, one at a time, for the arbiter's lifetime.
 *
 * Mandu-new (no reference origin).
 */
import { parentPort } from "node:worker_threads";
import { runDiscoveryJob, type DiscoveryJob, type DiscoveryWorkerReply } from "./secret-discovery-thread.js";

parentPort?.on("message", ({ id, job }: { id: number; job: DiscoveryJob }) => {
  let reply: DiscoveryWorkerReply;
  try {
    reply = { ok: true, report: runDiscoveryJob(job) };
  } catch (err) {
    reply = { ok: false, error: (err as Error).message };
  }
  parentPort?.postMessage({ id, reply });
});
