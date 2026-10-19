/**
 * secret-tainted-processes.test.ts — the `secretTaintedProcesses` op (plan 13
 * D6, a blind tunnel's chunks, 2026-10-07): the net-proxy's list of the
 * processes to look for among a tunnel's holders before each chunk, so that a
 * child forked after the CONNECT that reads a secret is judged as a sender
 * without a rescan of every process's descriptors per chunk.
 *
 * The list must never leave out a key `taintedProcessBindings` would call
 * tainted (the proxy judges only the holders it finds among the list and
 * their live descendants): it is the forward image of processSecretTaint's
 * backward walk. Asserted:
 *   - each edge kind carries taint forward (a raw-read row, the guard's
 *     lineage child, a claimed child, a flow receiver, a chain of them), and
 *     never backward (a reader's parent and an unrelated process stay out);
 *   - the property, over random graphs: a key is in the list exactly when
 *     processSecretTaint answers it tainted;
 *   - over IPC, from the DATA socket (the net-proxy's): the answer names
 *     process keys only, never a file or a byte; it is every session's.
 *
 * A real ProvenanceStore on a temp DB, and a real ArbiterServer with a real
 * ArbiterClient. Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { ProvenanceStore } from "../../provenance/provenance-store.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: raw reads are recorded

const sorted = (xs: string[]): string[] => [...xs].sort();

test("secretTaintedProcesses: a raw read, the guard's child, a claimed child and a flow receiver carry taint forward; never backward", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stp-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    assert.deepEqual(p.secretTaintedProcesses(), [], "nothing read yet");
    p.recordLineage("reader-1", "shell-0"); // the reader's parent
    p.recordLineage("other-9", "shell-0"); // its sibling, untainted
    p.taintProcessSecret({ procKey: "reader-1", path: "/w/.env", level: "no-model", app: "psql" });
    p.recordLineage("fork-2", "reader-1"); // the guard's edge (a fork that exec'd or opened)
    p.recordLineage("claim-3", "fork-2", undefined, { claimed: true }); // a data-socket claim
    p.recordProcessFlow("piped-4", ["claim-3"]); // received claim-3's bytes through a pipe
    p.recordLineage("grand-5", "piped-4"); // a child of the receiver
    p.recordProcessFlow("other-9", ["shell-0"]); // a flow from an untainted process
    assert.deepEqual(sorted(p.secretTaintedProcesses()), ["claim-3", "fork-2", "grand-5", "piped-4", "reader-1"]);
    for (const k of p.secretTaintedProcesses()) assert.notEqual(p.processSecretTaint(k).level, null, `${k} is tainted per the walk`);
    for (const k of ["shell-0", "other-9"]) assert.equal(p.processSecretTaint(k).level, null, `${k} is not`);
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secretTaintedProcesses: over random graphs a key is listed exactly when processSecretTaint answers it tainted", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stp-prop-"));
  try {
    let seed = 0x2a2a;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let round = 0; round < 25; round++) {
      const p = new ProvenanceStore({ dbPath: join(dir, `p${round}.db`) });
      try {
        const keys = Array.from({ length: 30 }, (_, i) => `k${round}-${i}`);
        for (let e = 0; e < 40; e++) {
          const a = keys[rnd(keys.length)]!;
          const b = keys[rnd(keys.length)]!;
          switch (rnd(4)) {
            case 0: p.recordLineage(a, b); break;
            case 1: p.recordLineage(a, b, undefined, { claimed: true }); break;
            case 2: p.recordProcessFlow(a, [b]); break;
            default: if (rnd(3) === 0) p.taintProcessSecret({ procKey: a, path: `/s/${b}`, level: "secret", app: "x" });
          }
        }
        const listed = new Set(p.secretTaintedProcesses());
        for (const k of keys) {
          assert.equal(listed.has(k), p.processSecretTaint(k).level !== null, `round ${round}: ${k}`);
        }
      } finally {
        p.close();
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secretTaintedProcesses: the kept walk is redone after any write, on this connection or another (never a stale list)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stp-memo-"));
  const db = join(dir, "p.db");
  const a = new ProvenanceStore({ dbPath: db });
  const b = new ProvenanceStore({ dbPath: db }); // another connection on the same file
  try {
    a.taintProcessSecret({ procKey: "m-1", path: "/w/.env", level: "no-model", app: "psql" });
    assert.deepEqual(a.secretTaintedProcesses(), ["m-1"]);
    assert.deepEqual(a.secretTaintedProcesses(), ["m-1"], "kept while nothing changed");
    a.recordLineage("m-2", "m-1");
    assert.deepEqual(sorted(a.secretTaintedProcesses()), ["m-1", "m-2"], "a write on this connection");
    b.recordProcessFlow("m-3", ["m-2"]);
    assert.deepEqual(sorted(a.secretTaintedProcesses()), ["m-1", "m-2", "m-3"], "a commit by another connection");
    b.taintProcessSecret({ procKey: "m-9", path: "/w/.env", level: "no-model", app: "psql" });
    assert.ok(a.secretTaintedProcesses().includes("m-9"));
    const got = a.secretTaintedProcesses();
    got.push("tampered");
    assert.ok(!a.secretTaintedProcesses().includes("tampered"), "the caller gets a copy");
  } finally {
    a.close();
    b.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secretTaintedProcesses over IPC from the data socket: process keys only, every session's", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-stp-ipc-"));
  const env = join(dir, ".env");
  const VALUE = "sk_live_stp_canary_8d1e";
  writeFileSync(env, `K=${VALUE}\n`);
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", bindings: ["bound.example"], readers: ["ssh-add"] }] },
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock"));
  const data = new ArbiterClient(join(dir, "a.sock"));
  await guard.connect();
  await data.connect();
  try {
    assert.deepEqual(await data.secretTaintedProcesses(), { procKeys: [] });
    assert.ok((await guard.registerSecret({ path: env })).symbol);
    assert.equal((await guard.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "stp-r-1", session: "sess-a" })).verdict, "raw");
    await guard.processLineage({ childKey: "stp-c-2", parentKey: "stp-r-1", session: "sess-b" });
    const r = await data.secretTaintedProcesses();
    assert.deepEqual(sorted(r.procKeys), ["stp-c-2", "stp-r-1"], "the reader and its recorded child, whatever their session");
    const wire = JSON.stringify(r);
    assert.ok(!wire.includes(VALUE) && !wire.includes(".env"), "no file and no byte");
  } finally {
    guard.close();
    data.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
