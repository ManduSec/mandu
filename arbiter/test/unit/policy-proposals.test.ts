/**
 * policy-proposals.test — the proposal queue and change log persist in
 * mandu.db (policy-surface.md §8.4.5): a restart keeps pending
 * proposals, their verdicts and the changes Undo needs, and fresh ids never
 * collide with persisted ones. No protection axis is involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import Database from "../../db/sqlite.js";
import { PolicyProposalStore, SUGGEST_SCANS_MAX } from "../../policy/policy-proposals.js";
import { openSymbolDb } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4); none is read

test("proposals and changes survive a restart; ids continue past the persisted ones", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-proposals-"));
  const dbPath = join(dir, "mandu.db");
  try {
    openSymbolDb(dbPath).close(); // the arbiter opens (and stamps) the file first
    const a = new PolicyProposalStore({ dbPath, now: () => 1000 });
    const p = a.file({
      edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }],
      reason: "$MDU:WebFetch[ab12].content says so", requestedBy: "agent:s1", sessionKey: "s1",
      relaxes: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "d" }], tightens: [],
      editsHash: "h1", lawHash: "l1",
    });
    const q = a.file({ edits: [], reason: null, requestedBy: "agent:s2", sessionKey: "s2", relaxes: [], tightens: [], editsHash: "h2", lawHash: "l1" });
    a.resolveProposal(q.id, "denied", "human");
    const c = a.recordChange({ via: "agent-tighten", requestedBy: "agent:s1", sessionKey: "s1", edits: [], delta: [], revert: [{ section: "paths", key: "/x", before: null, after: { path: "/x", level: "no-model" } }], proposalId: null });
    a.close();

    const b = new PolicyProposalStore({ dbPath, now: () => 2000 });
    assert.equal(b.getProposal(p.id)?.status, "pending");
    assert.equal(b.getProposal(p.id)?.reason, "$MDU:WebFetch[ab12].content says so", "stored as written, symbols included");
    assert.equal(b.getProposal(q.id)?.status, "denied");
    assert.equal(b.pendingWithEdits("h1")?.id, p.id);
    assert.equal(b.tighteningsBy("s1"), 1);
    assert.deepEqual(b.getChange(c.id)?.revert[0]?.after, { path: "/x", level: "no-model" });
    const r = b.file({ edits: [], reason: null, requestedBy: "agent:s3", sessionKey: "s3", relaxes: [], tightens: [], editsHash: "h3", lawHash: "l1" });
    assert.notEqual(r.id, p.id);
    assert.notEqual(r.id, q.id);
    b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("plan 14 §5.5: the last finished suggest scan per root survives a restart, newest SUGGEST_SCANS_MAX kept, junk rows ignored", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-proposals-"));
  const dbPath = join(dir, "mandu.db");
  try {
    openSymbolDb(dbPath).close();
    const a = new PolicyProposalStore({ dbPath });
    assert.equal(a.suggestScansFinished().size, 0, "a fresh file: no scan has finished");
    a.recordSuggestScan(["/home/u/proj", "/home/u/other"], 1000);
    a.recordSuggestScan(["/home/u/proj"], 2000);
    assert.deepEqual([...a.suggestScansFinished()].sort(), [["/home/u/other", 1000], ["/home/u/proj", 2000]]);
    a.close();

    // Rows a scan never writes (a relative root, a non-numeric time) are not read.
    const raw = new Database(dbPath);
    raw.prepare("INSERT INTO suggest_scans (root, finished_at) VALUES (?, ?)").run("relative/root", 5);
    raw.prepare("INSERT INTO suggest_scans (root, finished_at) VALUES (?, ?)").run("/home/u/text-time", "soon");
    raw.close();

    const b = new PolicyProposalStore({ dbPath });
    assert.deepEqual([...b.suggestScansFinished()].sort(), [["/home/u/other", 1000], ["/home/u/proj", 2000]], "the restart keeps both roots' times");
    // The cap: the oldest roots go, in memory and on disk.
    for (let i = 0; i < SUGGEST_SCANS_MAX; i++) b.recordSuggestScan([`/r/${i}`], 3000 + i);
    assert.equal(b.suggestScansFinished().size, SUGGEST_SCANS_MAX);
    assert.equal(b.suggestScansFinished().has("/home/u/other"), false, "the oldest went first");
    assert.equal(b.suggestScansFinished().has("/home/u/proj"), false);
    b.close();
    const c = new PolicyProposalStore({ dbPath });
    assert.equal(c.suggestScansFinished().size, SUGGEST_SCANS_MAX);
    assert.equal(c.suggestScansFinished().get(`/r/${SUGGEST_SCANS_MAX - 1}`), 3000 + SUGGEST_SCANS_MAX - 1);
    c.close();
    // In memory only (unit fixtures): kept for the store's life.
    const m = new PolicyProposalStore();
    m.recordSuggestScan(["/x"], 7);
    assert.equal(m.suggestScansFinished().get("/x"), 7);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
