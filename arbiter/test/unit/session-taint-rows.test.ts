/**
 * session-taint-rows — the provenance store's `session` rows (a HIGH
 * session's command holds what the session read; confidentiality.md §4,
 * "What Allow once means for a command"): they count for the process's
 * exits (its level, its children), never for what the model gets back
 * (`modelVisibleRows`, the held-session fallback), never for a raw read
 * (`attestedOnly`), and a real raw read or a claim of one replaces them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProvenanceStore, modelVisibleRows } from "../../provenance/provenance-store.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure store logic; stated for the manifest rule

function withStore(fn: (s: ProvenanceStore) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mdu-session-rows-"));
  const store = new ProvenanceStore({ dbPath: join(dir, "p.sqlite") });
  try {
    fn(store);
  } finally {
    store.close?.();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a session row taints the process and its children, but masks nothing the model gets back", () => {
  withStore((s) => {
    s.taintProcessSession("k-root", [{ path: "/h/memos/q3.md", level: "any-model" }, { path: "symbol:$MDU:anymodel_X[1a2b]", level: "any-model" }], "sess");
    s.recordExecRoot({ procKey: "k-child", parentKey: "k-root", signature: "curl", session: "sess" });
    const t = s.processSecretTaint("k-child");
    assert.equal(t.level, "any-model");
    assert.deepEqual(t.rows.map((r) => [r.path, r.via, r.app]).sort(), [["/h/memos/q3.md", "session", "session"], ["symbol:$MDU:anymodel_X[1a2b]", "session", "session"]]);
    assert.deepEqual(modelVisibleRows(t.rows), [], "the model already holds it");
    assert.equal(s.processSecretTaint("k-child", { attestedOnly: true }).level, null, "a session row never buys a raw read");
    assert.equal(s.heldSessionTaint("sess").level, null, "nor masks a call whose tree is not found");
  });
});

test("a real raw read, or a claim of one, on the same file replaces the session row and masks", () => {
  withStore((s) => {
    s.taintProcessSession("k1", [{ path: "/h/memos/q3.md", level: "any-model" }], "sess");
    s.taintProcessSecret({ procKey: "k1", path: "/h/memos/q3.md", level: "any-model", app: "cat", session: "sess", via: "reader" });
    assert.deepEqual(modelVisibleRows(s.processSecretTaint("k1").rows).map((r) => r.app), ["cat"]);
    s.taintProcessSession("k2", [{ path: "/h/memos/q3.md", level: "any-model" }], "sess");
    s.taintProcessSecret({ procKey: "k2", path: "/h/memos/q3.md", level: "any-model", app: "cat", session: "sess", claimed: true });
    assert.equal(modelVisibleRows(s.processSecretTaint("k2").rows).length, 1, "a claimed read masks too");
    // and a session row never overwrites a read already recorded
    s.taintProcessSession("k1", [{ path: "/h/memos/q3.md", level: "any-model" }], "sess");
    assert.equal(modelVisibleRows(s.processSecretTaint("k1").rows).length, 1);
  });
});

// arbiter-human-plane.md §5.2 (2026-10-17): from a channel whose reports are
// claims (a guard with no human plane), a HIGH session's command is still a
// holder, its rows marked claimed. A session row only confines, so the claim
// confines the same way, masks nothing and buys no raw read; the guard's own
// (believed) report of the row clears the mark.
test("a claimed session row confines like the guard's, masks nothing, buys no raw read, and a believed report clears the mark", () => {
  withStore((s) => {
    const claimedOf = (k: string): Array<number | null> =>
      ((s as unknown as { db: { prepare(q: string): { all(...a: unknown[]): unknown[] } } }).db
        .prepare(`SELECT claimed FROM process_secret_taint WHERE proc_key = ? ORDER BY path`).all(k) as Array<{ claimed: number | null }>).map((r) => r.claimed);
    s.taintProcessSession("c-root", [{ path: "/h/memos/q3.md", level: "any-model" }], "sess", { claimed: true });
    s.recordExecRoot({ procKey: "c-child", parentKey: "c-root", signature: "curl", session: "sess" });
    const t = s.processSecretTaint("c-child");
    assert.equal(t.level, "any-model", "its children hold the session's reads: their exits are judged");
    assert.deepEqual(t.rows.map((r) => r.via), ["session"]);
    assert.deepEqual(modelVisibleRows(t.rows), [], "a claim masks nothing the model gets back");
    assert.equal(s.processSecretTaint("c-child", { attestedOnly: true }).level, null, "nor buys a raw read");
    assert.deepEqual(claimedOf("c-root"), [1]);
    s.taintProcessSession("c-root", [{ path: "/h/memos/q3.md", level: "any-model" }], "sess");
    assert.deepEqual(claimedOf("c-root"), [null], "the guard's report is believed over the claim");
    // a claim never takes a believed row's place
    s.taintProcessSession("c-root", [{ path: "/h/memos/q3.md", level: "any-model" }], "sess", { claimed: true });
    assert.deepEqual(claimedOf("c-root"), [null]);
  });
});
