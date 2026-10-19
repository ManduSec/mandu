/**
 * secret-discovery-thread.test — the `discoverSecrets` walk on a worker thread
 * (runtime-instances.md §14.2 item 7): the one long-lived thread answers exactly what
 * the in-process walk answers over the same label snapshot, walk after walk
 * and for walks sent together; a thread that cannot start or dies falls back
 * to the in-process walk; a walk that throws is that error and the thread
 * serves on; a stopped thread rejects without a fallback. And the label
 * composition the worker uses is the arbiter's own (label-lookup.ts). The
 * file's process exiting at all is the check that an idle thread does not
 * hold the event loop.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  DiscoveryWorker, discoveryWorkerEntry, runDiscoveryJob, type DiscoveryJob,
} from "../../policy/secret-discovery-thread.js";
import { discoverSecretsReport } from "../../policy/secret-discovery.js";
import { composedLabel, snapshotLookup, type LabelSnapshot } from "../../policy/label-lookup.js";
import type { PathLabel } from "../../policy/path-labels.js";
import type { DerivedLabel } from "../../policy/derived-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4): confidentiality ON

const human = (path: string, confidentiality: PathLabel["confidentiality"]): PathLabel => ({
  path, confidentiality, bindings: [], recursive: true, source: "user", updatedAt: 1,
});
const derived = (path: string, confidentiality: DerivedLabel["confidentiality"]): DerivedLabel => ({
  path, confidentiality, bindings: [], sessionKey: "s", tool: null, sources: null, createdAt: 1, updatedAt: 1,
});

/** A home with a catalog match, a declassified catalog match, a user-labeled
 *  plain file, a machine-tainted plain file and a declared client key. */
function fixture(): { dir: string; home: string; job: DiscoveryJob } {
  const dir = mkdtempSync(join(tmpdir(), "mdu-disc-thread-"));
  const home = join(dir, "home");
  mkdirSync(join(home, "proj", "fixtures"), { recursive: true });
  mkdirSync(join(home, ".ssh"), { recursive: true });
  writeFileSync(join(home, ".ssh", "id_ed25519"), "k\n");
  writeFileSync(join(home, "proj", ".env"), "A=1\n");
  writeFileSync(join(home, "proj", "fixtures", ".env"), "FAKE=1\n");
  writeFileSync(join(home, "proj", "contract.txt"), "c\n");
  writeFileSync(join(home, "proj", "tainted.txt"), "t\n");
  const key = join(dir, "tls", "client.key");
  mkdirSync(join(dir, "tls"), { recursive: true });
  writeFileSync(key, "K\n");
  const labels: LabelSnapshot = {
    human: new Map([
      [join(home, "proj", "fixtures"), human(join(home, "proj", "fixtures"), "public")],
      [join(home, "proj", "contract.txt"), human(join(home, "proj", "contract.txt"), "local-model")],
    ]),
    derived: new Map([[join(home, "proj", "tainted.txt"), derived(join(home, "proj", "tainted.txt"), "no-model")]]),
    clientKeys: [key],
  };
  return { dir, home, job: { roots: [home, key], home, opts: {}, labels } };
}

test("the thread answers exactly what the in-process walk answers, walk after walk and for walks sent together", async () => {
  const { dir, home, job } = fixture();
  const fallbacks: string[] = [];
  const w = new DiscoveryWorker({ onFallback: (why) => fallbacks.push(why) });
  try {
    w.warm();
    const off = await w.run(job);
    const inProcess = discoverSecretsReport(job.roots, home, snapshotLookup(job.labels), job.opts);
    assert.deepEqual(off, inProcess);
    assert.deepEqual(off, runDiscoveryJob(job));
    const paths = off.files.map((f) => f.path);
    assert.ok(paths.includes(join(home, ".ssh", "id_ed25519")), "catalog");
    assert.ok(paths.includes(join(home, "proj", ".env")), "catalog");
    assert.ok(!paths.includes(join(home, "proj", "fixtures", ".env")), "a public human label declassifies");
    assert.ok(paths.includes(join(home, "proj", "contract.txt")), "a human label makes a plain file a secret");
    assert.ok(paths.includes(join(home, "proj", "tainted.txt")), "a derived label raises");
    assert.ok(paths.includes(job.roots[1]!), "the declared client key");
    // Together: each answer is matched to its own job.
    const noKey = { ...job, roots: [home], labels: { ...job.labels, clientKeys: [] } };
    const [a, b] = await Promise.all([w.run(job), w.run(noKey)]);
    assert.deepEqual(a, runDiscoveryJob(job));
    assert.deepEqual(b, runDiscoveryJob(noKey));
    assert.ok(!b.files.some((f) => f.path === job.roots[1]));
    assert.deepEqual(fallbacks, [], "every walk ran on the thread");
  } finally {
    w.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no worker entry, one that fails to load, or one that exits: the in-process walk, the same answer", async () => {
  const { dir, job } = fixture();
  const why: string[] = [];
  const workers: DiscoveryWorker[] = [];
  try {
    const run = async (entry: URL | null): Promise<void> => {
      const w = new DiscoveryWorker({ entry, onFallback: (x) => why.push(x) });
      workers.push(w);
      assert.deepEqual(await w.run(job), runDiscoveryJob(job));
    };
    await run(null);
    const broken = join(dir, "broken.mjs");
    writeFileSync(broken, "throw new Error('cannot load');\n");
    await run(pathToFileURL(broken));
    const silent = join(dir, "silent.mjs");
    writeFileSync(silent, "// exits without answering\n");
    await run(pathToFileURL(silent));
    assert.equal(why.length, 3, why.join("\n"));
    assert.match(why[0]!, /no worker entry/);
    assert.match(why[1]!, /cannot load/);
    assert.match(why[2]!, /exited/);
  } finally {
    for (const w of workers) w.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a walk that throws on the thread is that error, not a silent fallback, and the thread serves on", async () => {
  const { dir, job } = fixture();
  const why: string[] = [];
  const w = new DiscoveryWorker({ onFallback: (x) => why.push(x) });
  try {
    const broken = { ...job, roots: 5 as unknown as string[] };
    await assert.rejects(w.run(broken), /roots\.map is not a function/);
    assert.deepEqual(await w.run(job), runDiscoveryJob(job));
    assert.deepEqual(why, []);
  } finally {
    w.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stopped thread rejects its pending and later walks and does not walk in-process", async () => {
  const { dir, job } = fixture();
  const why: string[] = [];
  const w = new DiscoveryWorker({ onFallback: (x) => why.push(x) });
  try {
    const p = w.run(job);
    w.stop();
    await assert.rejects(p, /arbiter closing/);
    await assert.rejects(w.run(job), /arbiter closing/);
    assert.deepEqual(why, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the worker entry is found beside the module in its own form, and only there", () => {
  const here = discoveryWorkerEntry();
  assert.ok(here?.pathname.endsWith("/policy/secret-discovery-worker.ts"), String(here));
  const dir = mkdtempSync(join(tmpdir(), "mdu-disc-entry-"));
  try {
    const self = pathToFileURL(join(dir, "arbiter.mjs")).href;
    assert.equal(discoveryWorkerEntry(self), null, "a bundle with no worker beside it");
    writeFileSync(join(dir, "secret-discovery-worker.mjs"), "");
    assert.equal(discoveryWorkerEntry(self)?.href, pathToFileURL(join(dir, "secret-discovery-worker.mjs")).href);
    assert.equal(discoveryWorkerEntry(pathToFileURL(join(dir, "server.js")).href), null, "the compiled form looks for .js");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("label composition: a human label decides, a client key is no-model otherwise, a derived label never lowers it", () => {
  const key = "/keys/client.key";
  const s = (h: PathLabel[], d: DerivedLabel[]): LabelSnapshot => ({
    human: new Map(h.map((l) => [l.path, l])), derived: new Map(d.map((l) => [l.path, l])), clientKeys: [key],
  });
  assert.equal(composedLabel(key, s([], []))?.level, "no-model");
  assert.equal(composedLabel(key, s([human(key, "public")], []))?.level, "public", "the human label decides");
  assert.equal(composedLabel(key, s([], [derived(key, "local-model")]))?.level, "no-model", "a derived label does not lower it");
  assert.equal(composedLabel("/other", s([], [])), null);
  assert.equal(composedLabel("/other", s([], [derived("/other", "local-model")]))?.origin, "derived");
});
