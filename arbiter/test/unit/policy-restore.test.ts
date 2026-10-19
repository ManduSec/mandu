/**
 * policy-restore.test — a DECLINED policy.yaml relaxation never becomes the
 * law, not even after a restart (sandbox-security-review-2026-09-28 finding
 * 2's residual; policy-restore.ts; docs/design/architecture/write-protection.md §6).
 *
 * Pins:
 *   - the pure decisions: `decideDenyRestore` (restore only while the file
 *     still holds the declined bytes) and `decideStartupLaw` (a denied row
 *     restores, a pending row holds, an unnamed edit is the file's law);
 *   - deny writes the law in force back atomically, keeps the file's mode,
 *     re-creates a file whose removal was declined, and audits `restore`;
 *   - a newer edit that raced the deny is judged as a fresh edit (held anew,
 *     or applied when it tightens), never clobbered;
 *   - over a REAL mandu.db (the proposal store closed and reopened): a
 *     declined file found at start is restored before it is loaded; a start
 *     whose restore cannot write keeps the declined content out of force;
 *     an edit no row names is still the law at start (the documented
 *     residual); a record that no longer validates refuses the start;
 *   - the data plane never reads a held change's text.
 *
 * No privilege. The restore is axis-independent (the store never reads the
 * axes); the suite states `injection` because every suite states its axes.
 */
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { compilePolicy, getCurrentPolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { contentHash, parseEnforcedAtStart, PolicyDocumentStore, type PolicyChange } from "../../policy/policy-document-store.js";
import { PolicyProposalStore } from "../../policy/policy-proposals.js";
import { loadPolicyFileStrict, PolicyFileError } from "../../policy/policy-file-validate.js";
import { decideDenyRestore, decideStartupLaw, reconcilePolicyFileAtStart } from "../../policy/policy-restore.js";
import { PolicyAgentOps } from "../../ipc/policy-agent-ops.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // stated, never read: the restore is axis-independent

const INITIAL: PolicyFileConfig = { version: 1, paths: [{ path: "/home/u/repo/.env", level: "no-model" }] };
const INITIAL_TEXT = yaml.dump(INITIAL);
const RELAX_TEXT = INITIAL_TEXT + "user_rules:\n  - { id: hand, kind: release, to: { host: attacker.example }, mode: allow }\n";
const RELAX2_TEXT = INITIAL_TEXT + "user_rules:\n  - { id: other, kind: release, to: { host: paste.example }, mode: allow }\n";
const TIGHT_TEXT = "version: 1\npaths:\n  - { path: /home/u/repo/.env, level: no-model }\n  - { path: /home/u/repo/id_rsa, level: no-model }\n";

let dir: string;
let file: string;
let dbPath: string;
let docs: PolicyDocumentStore | undefined;
let proposals: PolicyProposalStore;
let proposalsOpen = false;

/** Stop the arbiter's policy half (idempotent). */
function stop(): void {
  docs?.close();
  docs = undefined;
  if (proposalsOpen) proposals.close();
  proposalsOpen = false;
}
let ops: PolicyAgentOps;
let logs: string[];
let audits: PolicyChange[];
let bump = 0;

function rebuild(doc: PolicyFileConfig | null): void {
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: doc }));
}

function writeDisk(text: string): void {
  writeFileSync(file, text);
  const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
  utimesSync(file, t, t);
}

const ruleIds = (): string[] => getCurrentPolicy().userRules.map((r) => r.id);

/** Start the arbiter's policy half as server.ts does: reopen mandu.db,
 *  reconcile the file, load the law, build the store and the surface. */
function start(): ReturnType<typeof reconcilePolicyFileAtStart> {
  stop();
  proposals = new PolicyProposalStore({ dbPath });
  proposalsOpen = true;
  const at = reconcilePolicyFileAtStart({ path: file, enforced: proposals.enforcedPolicy(file), diskRows: proposals.listProposals() });
  const doc = at.inForce ? parseEnforcedAtStart(file, at.inForce) : loadPolicyFileStrict(file).config;
  rebuild(doc);
  docs = new PolicyDocumentStore(
    {
      path: file, rebuild, pollMs: 0,
      log: (m) => logs.push(m),
      audit: (c) => audits.push(c),
      persistEnforced: (e) => proposals.recordEnforced(file, e),
    },
    { document: doc, found: at.inForce ? at.inForce.text !== null : existsSync(file), inForce: at.inForce, declined: at.declined },
  );
  ops = new PolicyAgentOps({ docs: docs!, proposals, pendingAsks: () => [], dbLabels: () => [], ruleHits: () => ({}), hostOf: (d) => d });
  return at;
}

function holdAndDeny(text: string): { id: string; restored: boolean | undefined } {
  writeDisk(text);
  assert.equal(docs!.pollDisk(), true);
  const [p] = ops.proposalsList("pending").proposals;
  assert.ok(p, "the relaxation is held");
  const r = ops.resolve(p.id, "denied", "dashboard");
  return { id: p.id, restored: r.restored };
}

beforeEach(() => {
  stop();
  if (dir) {
    try { chmodSync(dir, 0o700); } catch { /* ignore */ }
    rmSync(dir, { recursive: true, force: true });
  }
  dir = mkdtempSync(join(tmpdir(), "mandu-policy-restore-"));
  file = join(dir, "policy.yaml");
  dbPath = join(dir, "mandu.db");
  writeFileSync(file, INITIAL_TEXT);
  logs = [];
  audits = [];
  start();
});

after(() => {
  stop();
  if (dir) {
    try { chmodSync(dir, 0o700); } catch { /* ignore */ }
    rmSync(dir, { recursive: true, force: true });
  }
  resetCurrentPolicyForTests("claude-code");
});

// ── the pure decisions ─────────────────────────────────────────────────────

test("decideDenyRestore: restore only while the file holds the declined bytes and they are not the law", () => {
  assert.deepEqual(decideDenyRestore({ diskHash: "d", deniedHash: "d", inForceHash: "law" }), { restore: true });
  assert.deepEqual(decideDenyRestore({ diskHash: "newer", deniedHash: "d", inForceHash: "law" }), { restore: false, why: "moved-on" });
  assert.deepEqual(decideDenyRestore({ diskHash: "d", deniedHash: "d", inForceHash: "d" }), { restore: false, why: "matches-law" });
  assert.deepEqual(decideDenyRestore({ diskHash: "d", deniedHash: "d", inForceHash: null }), { restore: false, why: "no-law" });
  assert.deepEqual(decideDenyRestore({ diskHash: "absent", deniedHash: "absent", inForceHash: "law" }), { restore: true }, "a declined removal re-creates the file");
});

test("decideStartupLaw: denied restores, pending holds, an unnamed edit or no record is the file", () => {
  const enforced = { hash: "law", text: "version: 1\n" };
  const rows = [
    { id: "pp-1", status: "denied", diskHash: "d" },
    { id: "pp-2", status: "pending", diskHash: "p" },
    { id: "pp-3", status: "superseded", diskHash: "s" },
    { id: "pp-4", status: "pending", diskHash: null },
  ];
  assert.deepEqual(decideStartupLaw({ diskHash: "law", enforced, diskRows: rows }), { law: "file" }, "the file is the law in force");
  assert.deepEqual(decideStartupLaw({ diskHash: "d", enforced, diskRows: rows }), { law: "enforced", restoreFile: true, proposalId: "pp-1", status: "denied" });
  assert.deepEqual(decideStartupLaw({ diskHash: "p", enforced, diskRows: rows }), { law: "enforced", restoreFile: false, proposalId: "pp-2", status: "pending" });
  assert.deepEqual(decideStartupLaw({ diskHash: "s", enforced, diskRows: rows }), { law: "file" }, "a superseded row decides nothing");
  assert.deepEqual(decideStartupLaw({ diskHash: "x", enforced, diskRows: rows }), { law: "file" }, "an edit made while down that no row names");
  assert.deepEqual(decideStartupLaw({ diskHash: "d", enforced: null, diskRows: rows }), { law: "file" }, "no record (an older arbiter): the file");
  assert.equal(
    decideStartupLaw({ diskHash: "d", enforced, diskRows: [{ id: "a", status: "pending", diskHash: "d" }, { id: "b", status: "denied", diskHash: "d" }] }).law === "enforced" &&
      (decideStartupLaw({ diskHash: "d", enforced, diskRows: [{ id: "a", status: "pending", diskHash: "d" }, { id: "b", status: "denied", diskHash: "d" }] }) as { restoreFile: boolean }).restoreFile,
    true,
    "a denied row wins over a pending one for the same bytes",
  );
});

// ── deny while running ─────────────────────────────────────────────────────

test("deny writes the law back, keeps the file's mode, audits `restore`, and the row keeps the text", () => {
  chmodSync(file, 0o640);
  const { id, restored } = holdAndDeny(RELAX_TEXT);
  assert.equal(restored, true);
  assert.equal(readFileSync(file, "utf8"), INITIAL_TEXT);
  assert.equal(statSync(file).mode & 0o777, 0o640, "the mode is kept");
  assert.deepEqual(ruleIds(), []);
  const restoreAudit = audits.find((a) => a.via === "restore");
  assert.ok(restoreAudit, "a config_change audit says the file was restored");
  assert.match(restoreAudit!.summary, /declined/);
  assert.equal(ops.proposalsList("denied").proposals.find((p) => p.id === id)?.diskText, RELAX_TEXT, "admin: the declined hand edit is recoverable");
  assert.equal(docs!.pollDisk(), false, "the arbiter's own restore is not judged");
  assert.deepEqual(proposals.enforcedPolicy(file), { hash: contentHash(INITIAL_TEXT), text: INITIAL_TEXT });
});

test("the data plane never reads a held change's text", () => {
  writeDisk(RELAX_TEXT);
  docs!.pollDisk();
  const [admin] = ops.proposalsList("pending", "admin").proposals;
  const [data] = ops.proposalsList("pending", "data").proposals;
  assert.equal(admin!.diskText, RELAX_TEXT);
  assert.equal("diskText" in data!, false);
  assert.equal(data!.diskHash, admin!.diskHash);
});

test("a declined removal re-creates the file with the law in force", () => {
  rmSync(file);
  assert.equal(docs!.pollDisk(), true);
  const [p] = ops.proposalsList("pending").proposals;
  assert.equal(p!.diskHash, "absent");
  assert.equal(p!.diskText, null);
  const r = ops.resolve(p!.id, "denied", "dashboard");
  assert.equal(r.restored, true);
  assert.equal(readFileSync(file, "utf8"), INITIAL_TEXT);
  assert.ok(getCurrentPolicy().pathLabels.has("/home/u/repo/.env"));
});

test("a newer relaxing edit that raced the deny is held as a fresh edit, never clobbered", () => {
  writeDisk(RELAX_TEXT);
  docs!.pollDisk();
  const [p] = ops.proposalsList("pending").proposals;
  writeDisk(RELAX2_TEXT); // lands before the human's click; not polled yet
  const r = ops.resolve(p!.id, "denied", "dashboard");
  assert.equal(r.proposal.status, "denied");
  assert.equal(r.restored, false);
  assert.equal(readFileSync(file, "utf8"), RELAX2_TEXT, "the newer edit is left for the human");
  const [next, ...rest] = ops.proposalsList("pending").proposals;
  assert.equal(rest.length, 0);
  assert.equal(next!.diskHash, contentHash(RELAX2_TEXT), "judged afresh: its own card");
  assert.deepEqual(ruleIds(), []);
});

test("a newer tightening that raced the deny applies as a fresh edit", () => {
  writeDisk(RELAX_TEXT);
  docs!.pollDisk();
  const [p] = ops.proposalsList("pending").proposals;
  writeDisk(TIGHT_TEXT);
  const r = ops.resolve(p!.id, "denied", "dashboard");
  assert.equal(r.restored, false);
  assert.equal(readFileSync(file, "utf8"), TIGHT_TEXT);
  assert.ok(getCurrentPolicy().pathLabels.has("/home/u/repo/id_rsa"), "the tightening is the law");
  assert.deepEqual(proposals.enforcedPolicy(file), { hash: contentHash(TIGHT_TEXT), text: TIGHT_TEXT }, "and the new content in force is recorded");
});

// ── restarts over a real mandu.db ──────────────────────────────────────────

test("restart: the declined content, written back while the arbiter was down, is restored before it loads", () => {
  const { id } = holdAndDeny(RELAX_TEXT);
  docs!.close();
  writeFileSync(file, RELAX_TEXT); // e.g. a program re-wrote it while the arbiter was down
  const at = start();
  assert.equal(at.restored, true);
  assert.equal(at.decision.law, "enforced");
  assert.match(at.note ?? "", new RegExp(id));
  assert.equal(readFileSync(file, "utf8"), INITIAL_TEXT, "restored before loading");
  assert.deepEqual(ruleIds(), [], "the declined change is NOT the law after the restart");
  assert.equal(docs!.heldChange, null);
  assert.equal(ops.proposalsList("pending").proposals.length, 0, "no new card");
});

test("restart: a start whose restore cannot write keeps the declined content out of force", { skip: process.getuid?.() === 0 ? "root ignores directory permissions" : false }, () => {
  holdAndDeny(RELAX_TEXT);
  docs!.close();
  writeFileSync(file, RELAX_TEXT);
  chmodSync(dir, 0o500); // the temp file cannot be created
  try {
    const at = start();
    assert.equal(at.restored, false);
    assert.ok(at.inForce, "the persisted content is the law");
    assert.match(at.note ?? "", /WARNING/);
    assert.deepEqual(ruleIds(), [], "the declined change is NOT the law");
    assert.equal(ops.proposalsList("pending").proposals.length, 0, "no new card for declined content");
  } finally {
    chmodSync(dir, 0o700);
  }
  // Once the directory is writable again, the next poll restores the file.
  docs!.pollDisk();
  assert.equal(readFileSync(file, "utf8"), INITIAL_TEXT);
});

test("restart: an edit made while the arbiter was down that no row names is the law (the documented residual)", () => {
  docs!.close();
  writeFileSync(file, RELAX2_TEXT);
  const at = start();
  assert.equal(at.decision.law, "file");
  assert.deepEqual(ruleIds(), ["other"]);
  assert.deepEqual(proposals.enforcedPolicy(file), { hash: contentHash(RELAX2_TEXT), text: RELAX2_TEXT }, "it is the recorded content in force now");
});

test("restart: a recorded content in force that no longer validates refuses the start (never loads the declined file)", () => {
  holdAndDeny(RELAX_TEXT);
  docs!.close();
  writeFileSync(file, RELAX_TEXT);
  // The restore writes the recorded bytes back as they are; parsing them is
  // what refuses. Here the restore path is exercised through the parse alone.
  assert.throws(() => parseEnforcedAtStart(file, { hash: "stale", text: "version: 1\nnot_a_key: true\n" }), (e: unknown) => e instanceof PolicyFileError && /edit policy\.yaml/.test(e.problems[0]!));
  assert.equal(parseEnforcedAtStart(file, { hash: "absent", text: null }), null, "a recorded 'no file' is the built-ins");
});

test("restart with no record (an arbiter from before this change): the file is the law and gets recorded", () => {
  stop();
  rmSync(dbPath, { force: true });
  for (const s of ["-wal", "-shm"]) rmSync(`${dbPath}${s}`, { force: true });
  writeFileSync(file, RELAX_TEXT);
  const at = start();
  assert.equal(at.decision.law, "file");
  assert.deepEqual(ruleIds(), ["hand"]);
  assert.equal(proposals.enforcedPolicy(file)?.hash, contentHash(RELAX_TEXT));
});
