/**
 * session-path-labels — a session's machine label on one exact path
 * (policy/session-path-labels.ts; supported-agents.md §2.3 item 7): the store,
 * its composition into the ONE label lookup (label-lookup.ts), and the ops
 * through the REAL arbiter: `sessionPathLabel` (data plane, raise-only),
 * `clearSessionPathLabels` (human plane); the rows are NOT in
 * `derivedLabelsSince` (the kernel guard would twin the agent's own reads).
 *
 * The first producer is OpenCode 2's background output file, which the proxy
 * registers when it forwards the result that names it. The default location
 * of those files is a catalog location now (secret-catalog.ts); the session
 * label covers a path the catalog does not know, as OUT_ELSEWHERE here.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SessionPathLabelStore, SESSION_PATH_LABELS_MAX } from "../../policy/session-path-labels.js";
import { composedLabel, sessionLabel, type LabelSnapshot } from "../../policy/label-lookup.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis is what the label serves

const OUT = "/home/u/.local/share/opencode/shell/0123456789abcdef0123456789abcdef01234567/sh_10b1e7beb001nTybL5RlJg0o5t.out";
/** An output file in a place the catalog does not know (a future layout). */
const OUT_ELSEWHERE = "/var/tmp/agent-out/job-17/output.log";

test("store: exact absolute paths, idempotent (the first session's row stands), cleared per session, listed by change number", () => {
  const s = new SessionPathLabelStore();
  let g = 0;
  const next = () => ++g;
  assert.equal(s.set("rel/x.out", "a", "r", next), null, "relative: no identity");
  assert.equal(s.set(OUT, "", "r", next), null, "no session");
  const a = s.set(`${OUT}/`, "a", "first", next)!;
  assert.equal(a.path, OUT, "normalized");
  assert.equal(s.set(OUT, "b", "again", next), a, "idempotent: the first row stands");
  s.set("/tmp/other.out", "b", "r", next);
  assert.deepEqual(s.since(0).map((r) => r.path), [OUT, "/tmp/other.out"]);
  assert.deepEqual(s.since(a.gen).map((r) => r.path), ["/tmp/other.out"]);
  assert.equal(s.clearSession("b"), 1);
  assert.deepEqual(s.list().map((r) => r.path), [OUT]);
  assert.ok(SESSION_PATH_LABELS_MAX >= 10_000);
});

test("lookup: a session label makes the exact path no-model, bound nowhere, over a human label of any level (raise-only); a neighbour is untouched", () => {
  const session = new Map([[OUT, { path: OUT }]]);
  const human = new Map([[OUT, { path: OUT, confidentiality: "public", bindings: ["docs.corp"], recursive: false, source: "user", updatedAt: 0 }]]);
  const snap = { human, derived: new Map(), clientKeys: [], session } as unknown as LabelSnapshot;
  assert.deepEqual(composedLabel(OUT, snap), { level: "no-model", bindings: [], via: OUT, origin: "derived", overridesCatalog: false });
  assert.equal(sessionLabel(`${OUT}.bak`, snap), null);
  assert.equal(composedLabel(OUT, { ...snap, session: undefined })?.level, "public", "no session store: the human label decides");
});

async function withArbiter(fn: (data: ArbiterClient, human: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-labels-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), humanSocketPath: join(dir, "human.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  const human = new ArbiterClient(join(dir, "human.sock"));
  await data.connect();
  await human.connect();
  try {
    await fn(data, human);
  } finally {
    data.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("ops: the data plane labels a path (raise-only); every lookup and the shell-result classification see it, the guard's open index does not; only the human plane clears it", async () => {
  await withArbiter(async (data, human) => {
    const OUT = OUT_ELSEWHERE;
    assert.equal((await data.pathLevel(OUT)).level, "public", "before: nothing labels the file");
    const before = await data.derivedLabelsSince({});
    const r = await data.sessionPathLabel({ path: OUT, sessionKey: "oc2-s", reason: "OpenCode background output" });
    assert.deepEqual(r, { labeled: true, path: OUT, level: "no-model", reason: "OpenCode background output" });
    assert.equal((await data.pathLevel(OUT)).level, "no-model");
    // not in the kernel guard's index: it would twin OpenCode's own reads of the file
    const since = await data.derivedLabelsSince({ epoch: before.epoch, since: before.gen });
    assert.deepEqual(since.labels, []);
    // a read of it and a shell command naming it classify no-model (path-derived)
    const read = await data.classify({ tool: "read", value: "API_KEY=x", boundary: "model_context", origin: OUT, params: { path: OUT } });
    assert.equal(read.confidentiality, "no-model");
    const cat = await data.classify({ tool: "Bash", value: "API_KEY=x", boundary: "model_context", origin: `cat ${OUT}`, params: { command: `cat ${OUT}` } });
    assert.equal(cat.confidentiality, "no-model");
    // bad input
    await assert.rejects(() => data.sessionPathLabel({ path: "rel.out", sessionKey: "oc2-s" }), /absolute/);
    await assert.rejects(() => data.sessionPathLabel({ path: OUT, sessionKey: "" }), /sessionKey/);
    // clearing lowers protection: refused on the data socket, done on the human one
    await assert.rejects(() => data.clearSessionPathLabels({ sessionKey: "oc2-s" }), /human/i);
    assert.equal((await data.pathLevel(OUT)).level, "no-model", "still labelled");
    assert.deepEqual(await human.clearSessionPathLabels({ sessionKey: "oc2-s" }), { cleared: 1 });
    assert.equal((await data.pathLevel(OUT)).level, "public", "gone with the session");
  });
});
