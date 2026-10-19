/**
 * pipe-flow-taint.test.ts — confidentiality plan 13 D2, the arbiter half: a
 * process whose bytes came from a holder through a descriptor (a pipeline's
 * next stage, a FIFO's reader, a socket pair's other end) is NOT the
 * holder's descendant, so the parent walk (`processSecretTaint`) never found
 * its taint. The guard now names those writers as `flowsFrom` on the two
 * exits it asks about (`taintedProcessBindings`, `labelWrittenPathTainted`),
 * and the arbiter unions their taint in WITHOUT recording a lineage edge
 * (a pipe's writer is not its reader's parent: an edge would make the
 * reader's real parents and every later walk through them inherit it).
 *
 * Mandu-new test (no reference origin).
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

stateAxes("secrets"); // the confidentiality axis: where a pipe's bytes may go

test("processSecretTaintWithFlows: a writer's rows join the reader's own, and nothing is recorded", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d2-prov-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    p.taintProcessSecret({ procKey: "py-1", path: "/w/x.txt", level: "no-model", app: "python3" });
    p.recordLineage("py-1", "sh-0");
    p.recordLineage("curl-2", "sh-0");
    assert.equal(p.processSecretTaint("curl-2").level, null, "a sibling: the parent walk finds nothing (D2)");
    const t = p.processSecretTaintWithFlows("curl-2", ["py-1"]);
    assert.equal(t.level, "no-model");
    assert.deepEqual(t.rows.map((r) => r.path), ["/w/x.txt"]);
    assert.equal(p.processSecretTaint("curl-2").level, null, "no edge was recorded: the walk alone still finds nothing");
    assert.equal(p.processSecretTaint("sh-0").level, null, "and the shared parent is untouched");
    // An empty or unknown flow changes nothing.
    assert.deepEqual(p.processSecretTaintWithFlows("curl-2", []), p.processSecretTaint("curl-2"));
    assert.equal(p.processSecretTaintWithFlows("curl-2", ["nobody-9"]).level, null);
    // The writer's own ancestors count (it holds through them).
    p.taintProcessSecret({ procKey: "bash-5", path: "/w/.env", level: "any-model", app: "bash" });
    p.recordLineage("cat-6", "bash-5");
    const t2 = p.processSecretTaintWithFlows("grep-7", ["cat-6"]);
    assert.deepEqual(t2.rows.map((r) => r.path), ["/w/.env"]);
    // Both sources: the strictest level, each row once.
    const t3 = p.processSecretTaintWithFlows("tee-8", ["py-1", "cat-6", "py-1"]);
    assert.equal(t3.level, "no-model");
    assert.deepEqual(t3.rows.map((r) => r.path).sort(), ["/w/.env", "/w/x.txt"]);
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** The script the python3 reader runs, as the guard reports a pinnable one. */
const READER_PY = { path: "/opt/tools/reader.py", sha256: "b".repeat(64), system: true, isolated: true, traced: false };

async function withArbiter(fn: (c: ArbiterClient, x: string, dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-d2-"));
  const x = join(dir, "x.txt");
  writeFileSync(x, "API_KEY=d2canary0000000000000001\n");
  const sock = join(dir, "a.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    // Plan 13 §8 decision (b): python3 reads only as the script it runs.
    policyDocument: { version: 1, paths: [{ path: x, level: "no-model", readers: [{ app: "python3", script: READER_PY.path, prints: "nothing" }], bindings: ["api.example.com"] }] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxy's channel (plan 13 D9)
  await c.connect();
  try {
    assert.ok((await c.registerSecret({ path: x })).symbol);
    await fn(c, x, dir);
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("D2 network exit: a pipeline's next stage holds the reader's taint and bindings only through flowsFrom", async () => {
  await withArbiter(async (c, x) => {
    assert.equal((await c.decideSecretOpen({ path: x, exe: "/usr/bin/python3", isAgent: false, exeSystem: true, openerEnv: [], script: READER_PY, procKey: "d2-py-1", parentKey: "d2-sh-0" })).verdict, "raw");
    const sibling = await c.taintedProcessBindings({ procKey: "d2-curl-2", ancestors: ["d2-sh-0"] });
    assert.equal(sibling.tainted, false, "the parent walk alone: the sibling looks untainted (the bug the guard's flowsFrom closes)");
    const viaPipe = await c.taintedProcessBindings({ procKey: "d2-curl-2", ancestors: ["d2-sh-0"], flowsFrom: ["d2-py-1"] });
    assert.equal(viaPipe.tainted, true);
    assert.deepEqual(viaPipe.files, [x]);
    assert.deepEqual(viaPipe.bindings, ["api.example.com"], "it may send only where the file may go");
    // No edge was recorded: asked again without the flow, still untainted.
    assert.equal((await c.taintedProcessBindings({ procKey: "d2-curl-2" })).tainted, false);
    // A malformed flowsFrom is no flow (never a widening: the guard decides who holds).
    const bad = await c.taintedProcessBindings({ procKey: "d2-curl-3", flowsFrom: [42, { k: 1 }] as unknown as string[] });
    assert.equal(bad.tainted, false);
  });
});

test("D2 write exit: `reader | tee copy.txt` labels copy.txt at the reader's level", async () => {
  await withArbiter(async (c, x, dir) => {
    assert.equal((await c.decideSecretOpen({ path: x, exe: "/usr/bin/python3", isAgent: false, exeSystem: true, openerEnv: [], script: READER_PY, procKey: "d2-py-4", parentKey: "d2-sh-0" })).verdict, "raw");
    const copy = join(dir, "copy.txt");
    const unlabeled = await c.labelWrittenPathTainted({ path: copy, procKey: "d2-tee-5", ancestors: ["d2-sh-0"] });
    assert.equal(unlabeled.labeled, false, "without the flow, tee holds nothing (D2)");
    const labeled = await c.labelWrittenPathTainted({ path: copy, procKey: "d2-tee-5", ancestors: ["d2-sh-0"], flowsFrom: ["d2-py-4"] });
    assert.equal(labeled.labeled, true);
    assert.equal(labeled.level, "no-model");
    assert.equal((await c.pathLevel(copy)).level, "no-model", "a later read of copy.txt is judged at the file's level");
  });
});
