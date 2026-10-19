/**
 * policy-suggestion-ops.test — the store and the arbiter ops of plan 14's
 * suggestions (confidentiality-plan-14-policy-suggestions.md §5.1, §5.2),
 * over a REAL policy file, PolicyDocumentStore and a file-backed
 * PolicyProposalStore, with hand-built scan results.
 *
 * Pins:
 *   - filing: one row per secret, kind "suggestion", requested by
 *     "mandu:scan", with its finding key; an event per batch;
 *   - dedup: a pending key is not filed twice; a DISMISSED key is never
 *     filed again, across a restart of the store;
 *   - the cap: at most 20 pending per repository, the rest counted;
 *   - supersede: a pending suggestion the law now covers is closed on read;
 *   - mandu.db labels: a label that lives only in mandu.db (a dashboard
 *     act, a path that no longer exists) covers its path like a policy.yaml
 *     one, at filing, on read (superseded) and at apply (covered);
 *   - apply: a pure tightening applies (`via: "agent-tighten"` on the data
 *     plane, the agent's channel; `tighten` on the admin one), closes approved
 *     with the change id, and refuses a second time; covered closes;
 *     lock-blob is refused as unsupported until the grammar knows it; while
 *     a relaxing hand edit is held it applies to the law and to the held
 *     edit alike, which stays held with its comments (tour item 17);
 *   - resolvePolicyProposal on a suggestion: approve = apply (`via:
 *     "proposal"`), deny = dismiss;
 *   - suggestions stay out of the proposal list, the agent's pending caps
 *     and policyExplain; no client names `mandu:scan`; a loosening row is
 *     refused on every applySuggestion via, and a data-plane apply does not
 *     spend the agent's per-session tightening cap;
 *   - a table from before the columns gains them in place;
 *   - §13.4, the two sources: a file both scans find is one suggestion
 *     (history filed first), a dismissal of either blocks the other, the
 *     per-repository cap counts both, the answer carries the workspace
 *     summary (no findings); §13.5, the op: `sources` and `includeHome`
 *     validated, each source run alone, axis OFF answers
 *     `workspaceScan: null`.
 *
 * No privilege; the protection axes are not read by this code.
 */
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import Database from "../../db/sqlite.js";
import { compilePolicy, getCurrentPolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { PolicyDocumentStore } from "../../policy/policy-document-store.js";
import { POLICY_EDIT_OPS } from "../../policy/policy-edit.js";
import { PolicyProposalStore, SCAN_REQUESTER } from "../../policy/policy-proposals.js";
import { loadPolicyFileStrict } from "../../policy/policy-file-validate.js";
import type { SecretHistoryFinding, SecretHistoryScan } from "../../policy/secret-history-scan.js";
import { DEFAULT_HISTORY_LIMITS, defaultHistoryGitRunner, type HistoryGitRunner } from "../../policy/secret-history-scan.js";
import { DEFAULT_WORKSPACE_LIMITS, type SecretWorkspaceFinding, type SecretWorkspaceScan } from "../../policy/secret-workspace-scan.js";
import { ArbiterServer, earlierScanAt } from "../../ipc/server.js";
import type { SuggestPolicyResult } from "../../ipc/protocol.js";
import { OpError, PENDING_CAP_PER_SESSION, PolicyAgentOps } from "../../ipc/policy-agent-ops.js";
import { PolicySuggestionOps, SUGGESTION_CAP_PER_REPO, type SuggestionEvent } from "../../ipc/policy-suggestion-ops.js";
import type { PathLabel } from "../../policy/path-labels.js";
import type { PolicyEdit } from "../../policy/policy-edit.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const REPO = "/home/u/proj";
const OTHER = "/home/u/other";
const LOCK_BLOB_KNOWN = (POLICY_EDIT_OPS as readonly string[]).includes("lock-blob");

let dir: string;
let file: string;
let dbPath: string;
let docs: PolicyDocumentStore;
let proposals: PolicyProposalStore;
let ops: PolicySuggestionOps;
let agent: PolicyAgentOps;
let events: SuggestionEvent[];
let clock = Date.parse("2026-09-30T00:00:00Z");

function rebuild(doc: PolicyFileConfig | null): void {
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: doc }));
}

function wire(): void {
  events = [];
  ops = new PolicySuggestionOps({ docs, proposals, emit: (e) => events.push(e), exists: () => false, now: () => clock });
  agent = new PolicyAgentOps({
    docs, proposals, pendingAsks: () => [], dbLabels: () => [], ruleHits: () => ({}), hostOf: (d) => d,
    resolveSuggestion: (id, v, by) => ops.resolve(id, v, by), now: () => clock,
  });
}

beforeEach(() => {
  docs?.close();
  proposals?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = mkdtempSync(join(tmpdir(), "mandu-suggest-ops-"));
  file = join(dir, "policy.yaml");
  dbPath = join(dir, "mandu.db");
  writeFileSync(file, yaml.dump({ version: 1, paths: [{ path: "/home/u/repo/.env", level: "no-model" }] }));
  const loaded = loadPolicyFileStrict(file);
  rebuild(loaded.config);
  docs = new PolicyDocumentStore({ path: file, rebuild, pollMs: 0, log: () => {} }, { document: loaded.config, found: true });
  proposals = new PolicyProposalStore({ dbPath, now: () => clock++ });
  wire();
});

after(() => {
  docs?.close();
  proposals?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
  resetCurrentPolicyForTests("claude-code");
});

function finding(rel: string, over: Partial<SecretHistoryFinding> = {}): SecretHistoryFinding {
  const d = { kind: "content-shape" as const, rule: "github-token" as const, line: 1, preview: "ghp_…" };
  return {
    repoRoot: REPO, blob: "a".repeat(40), paths: [rel], firstCommit: "1".repeat(40), lastCommit: "2".repeat(40),
    inHead: false, inIndex: false, stillPresent: false, pathStillSecretByCatalog: false, detector: d, detectors: [d], ...over,
  };
}

function scanOf(findings: SecretHistoryFinding[], repos = [REPO]): SecretHistoryScan {
  return {
    repos: repos.map((r) => ({ root: r, repoRoot: r })),
    counts: { blobs: findings.length, scanned: findings.length, classified: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, readFailed: 0, binary: 0, pathsUnchecked: 0, untraced: 0, unlisted: false, lines: [] },
    findings, limits: DEFAULT_HISTORY_LIMITS, ms: 1,
  };
}

test("filing: one suggestion per secret, filed by mandu:scan with its finding key, one event", () => {
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa"), finding("covered.txt", { blob: "c".repeat(40), pathStillSecretByCatalog: true, stillPresent: true })]), { home: "/home/u" });
  assert.equal(r.axis, true);
  assert.equal(r.running, false);
  assert.equal(r.filed.length, 1);
  assert.deepEqual({ ...r.counts }, { findings: 2, suggested: 1, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 1, dropped: 0, superseded: 0 });
  const v = r.suggestions[0]!;
  assert.equal(v.kind, "suggestion");
  assert.equal(v.requestedBy, SCAN_REQUESTER);
  assert.equal(v.status, "pending");
  assert.equal(v.findingKey, `git-history:path:${REPO}/deploy/id_rsa`);
  assert.equal(v.sentence, "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)");
  assert.equal(v.applicable, true);
  assert.equal(r.covered.length, 1);
  assert.deepEqual(events, [{ action: "filed", ids: r.filed }]);
  const row = proposals.getProposal(v.id)!;
  assert.equal(row.kind, "suggestion");
  assert.deepEqual(row.relaxes, []);
  assert.ok(row.tightens.length > 0, "the delta at filing is kept");
});

test("dedup: a pending key is not filed twice; a dismissed key is never filed again, across a restart", () => {
  const scan = scanOf([finding("deploy/id_rsa")]);
  const first = ops.fileFromScan(scan);
  const again = ops.fileFromScan(scan);
  assert.equal(again.filed.length, 0);
  assert.equal(again.counts.alreadyPending, 1);
  assert.equal(again.suggestions.length, 1);

  const d = ops.dismiss(first.filed[0]!, "human:e2e");
  assert.equal(d.suggestion.status, "denied");
  assert.equal(d.suggestion.resolvedBy, "human:e2e");
  assert.deepEqual(events.at(-1), { action: "dismissed", ids: [first.filed[0]] });
  assert.throws(() => ops.dismiss(first.filed[0]!, "human:e2e"), OpError);

  // Restart: the store is rebuilt from mandu.db.
  proposals.close();
  proposals = new PolicyProposalStore({ dbPath, now: () => clock++ });
  wire();
  const after = ops.fileFromScan(scan);
  assert.equal(after.filed.length, 0);
  assert.equal(after.counts.dismissed, 1);
  assert.equal(ops.list("denied").suggestions[0]?.findingKey, `git-history:path:${REPO}/deploy/id_rsa`);
});

test(`the cap: at most ${SUGGESTION_CAP_PER_REPO} pending per repository, the rest counted`, () => {
  const many = Array.from({ length: SUGGESTION_CAP_PER_REPO + 5 }, (_, i) => finding(`k/${i}.pem`, { blob: i.toString(16).padStart(40, "0") }));
  const r = ops.fileFromScan(scanOf([...many, finding("x.pem", { repoRoot: OTHER })], [REPO, OTHER]));
  assert.equal(r.counts.filed, SUGGESTION_CAP_PER_REPO + 1);
  assert.equal(r.counts.overCap, 5);
  assert.equal(proposals.pendingSuggestionCount(REPO), SUGGESTION_CAP_PER_REPO);
  assert.equal(proposals.pendingSuggestionCount(OTHER), 1, "another repository has its own cap");
});

test("supersede: a pending suggestion the law now covers is closed on the next read", () => {
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa")]));
  const doc = structuredClone(docs.document!) as PolicyFileConfig;
  doc.paths!.push({ path: `${REPO}/deploy`, level: "no-model" });
  docs.apply(doc, { via: "apply", requestedBy: "human" });
  const listed = ops.list();
  assert.equal(listed.suggestions[0]?.status, "superseded");
  assert.deepEqual(events.at(-1), { action: "superseded", ids: r.filed });
  assert.equal(ops.list("pending").suggestions.length, 0);
});

test("apply: a pure tightening applies (agent-tighten on the data plane), closes approved with the change id, and only once", () => {
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa")]));
  const id = r.filed[0]!;
  const a = ops.apply(id, { via: "agent-tighten", by: "data-plane" });
  assert.equal(a.applied, true);
  assert.ok(a.applied && a.changeId);
  assert.equal(a.suggestion.status, "approved");
  assert.match(readFileSync(file, "utf8"), /\/home\/u\/proj\/deploy\/id_rsa/);
  const change = proposals.getChange(a.suggestion.changeId!)!;
  assert.equal(change.via, "agent-tighten", "the data plane is the agent's channel");
  assert.equal(change.proposalId, id);
  assert.equal(change.requestedBy, "data-plane");
  assert.deepEqual(events.at(-1), { action: "applied", ids: [id] });
  assert.throws(() => ops.apply(id, { via: "agent-tighten", by: "data-plane" }), /already approved/);
  // History names the scan as the proposer.
  assert.equal(agent.changesList(1).changes[0]?.proposedBy, SCAN_REQUESTER);
});

test("tour 17: apply while a relaxing hand edit is held — the lock is the law, the hand edit stays held in the file with the lock and its comments", () => {
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa")]));
  const id = r.filed[0]!;
  // A hand edit that relaxes (a standing allow rule): held, filed as a card.
  const hand = readFileSync(file, "utf8") + "# for the demo only\nuser_rules:\n  - { id: hand, kind: release, to: { host: paste.example }, mode: allow }  # until Friday\n";
  writeFileSync(file, hand);
  const t = new Date(Date.now() + 10_000);
  utimesSync(file, t, t);
  docs.pollDisk();
  const held = docs.heldChange;
  assert.ok(held, "held");
  const card = agent.proposalsList("pending").proposals[0]!;
  assert.equal(card.diskHash, held.hash);

  const a = ops.apply(id, { via: "agent-tighten", by: "data-plane" });
  assert.equal(a.applied, true, JSON.stringify(a));
  assert.equal(a.suggestion.status, "approved");
  assert.ok(getCurrentPolicy().pathLabels.has(`${REPO}/deploy/id_rsa`), "the suggestion is the law");
  assert.deepEqual(getCurrentPolicy().userRules.map((u) => u.id), [], "the held relaxation is not");
  const text = readFileSync(file, "utf8");
  const onDisk = yaml.load(text) as PolicyFileConfig;
  assert.ok(onDisk.paths!.some((p) => p.path === `${REPO}/deploy/id_rsa`), "the file has the lock");
  assert.deepEqual(onDisk.user_rules!.map((u) => u.id), ["hand"], "and the hand edit");
  assert.match(text, /# for the demo only\n/);
  assert.match(text, /# until Friday/);
  // Still waiting, filed again for the new bytes with no more than it showed.
  const [again] = agent.proposalsList("pending").proposals;
  assert.ok(again && again.id !== card.id && again.diskHash === docs.heldChange!.hash);
  assert.deepEqual(again.relaxes.map((x) => x.subject), card.relaxes.map((x) => x.subject));
});

test("apply: covered closes the suggestion; lock-blob waits for the grammar", () => {
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa")]));
  const doc = structuredClone(docs.document!) as PolicyFileConfig;
  doc.paths!.push({ path: `${REPO}/deploy/id_rsa`, level: "no-model" });
  docs.apply(doc, { via: "apply", requestedBy: "human" });
  const c = ops.apply(r.filed[0]!, { via: "agent-tighten", by: "data-plane" });
  assert.equal(c.applied, false);
  assert.equal(!c.applied && c.refused, "covered");
  assert.equal(c.suggestion.status, "superseded");

  const opsPresent = new PolicySuggestionOps({ docs, proposals, exists: () => true, now: () => clock });
  const b = opsPresent.fileFromScan(scanOf([finding("config.py", { blob: "b".repeat(40), stillPresent: true })]));
  const view = b.suggestions.find((s) => s.edits[0]?.op === "lock-blob")!;
  assert.equal(view.applicable, LOCK_BLOB_KNOWN);
  if (!LOCK_BLOB_KNOWN) {
    const u = opsPresent.apply(view.id, { via: "agent-tighten", by: "data-plane" });
    assert.equal(!u.applied && u.refused, "unsupported");
    assert.equal(u.suggestion.status, "pending", "it waits");
  }
});

/** A label that lives only in mandu.db (a dashboard act), as the
 *  PathLabelStore keeps it. */
function dbLabel(path: string, level: "no-model" | "local-model" | "any-model" | "public" = "no-model"): PathLabel {
  return { path, confidentiality: level, bindings: [], recursive: true, source: "user", updatedAt: clock };
}

/** The arbiter's label set in force: policy.yaml's, then mandu.db's rows. */
function withDbLabels(rows: PathLabel[]): () => ReadonlyMap<string, PathLabel> {
  return () => {
    const m = new Map(getCurrentPolicy().pathLabels);
    for (const l of rows) m.set(l.path, l);
    return m;
  };
}

test("a label only in mandu.db covers its path: no duplicate suggestion (a path that no longer exists, a folder above it)", () => {
  const scan = scanOf([finding("deploy/id_rsa"), finding("old/keys/a.pem", { blob: "b".repeat(40) }), finding("other.pem", { blob: "c".repeat(40) })]);
  // Without mandu.db's labels (the bug): the policy file alone, so all three are filed.
  const blind = ops.fileFromScan(scan);
  assert.equal(blind.counts.filed, 3, "the control: a policy-file-only check suggests a lock the person already made");
  proposals.close();
  rmSync(dbPath, { force: true });
  proposals = new PolicyProposalStore({ dbPath, now: () => clock++ });
  // With them: the exact label and the recursive folder label cover two; only the third is filed.
  const rows = [dbLabel(`${REPO}/deploy/id_rsa`), dbLabel(`${REPO}/old`, "any-model")];
  ops = new PolicySuggestionOps({ docs, proposals, emit: (e) => events.push(e), exists: () => false, now: () => clock, pathLabels: withDbLabels(rows) });
  const r = ops.fileFromScan(scan);
  assert.equal(r.counts.filed, 1, JSON.stringify(r.counts));
  assert.deepEqual(r.suggestions.flatMap((v) => v.edits.map((e) => (e as { path?: string }).path)), [`${REPO}/other.pem`]);
  assert.equal(r.counts.covered, 2, "the db labels count as coverage, like a policy.yaml label");
  assert.ok(!readFileSync(file, "utf8").includes("deploy/id_rsa"), "the label is not in policy.yaml");
  // A db label at public is no protection: the file is still suggested.
  const pub = new PolicySuggestionOps({ docs, proposals, exists: () => false, now: () => clock, pathLabels: withDbLabels([dbLabel(`${REPO}/pub.pem`, "public")]) });
  assert.equal(pub.fileFromScan(scanOf([finding("pub.pem", { blob: "d".repeat(40) })])).counts.filed, 1);
});

test("a label set in mandu.db after filing: the pending suggestion is closed superseded on read, and apply closes it covered", () => {
  const rows: PathLabel[] = [];
  ops = new PolicySuggestionOps({ docs, proposals, emit: (e) => events.push(e), exists: () => false, now: () => clock, pathLabels: withDbLabels(rows) });
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa"), finding("b/id_rsa", { blob: "b".repeat(40) })]));
  assert.equal(r.filed.length, 2);
  const idOf = (rel: string): string => r.suggestions.find((v) => v.edits.some((e) => (e as { path?: string }).path === `${REPO}/${rel}`))!.id;
  const [first, second] = [idOf("deploy/id_rsa"), idOf("b/id_rsa")];
  const lawBefore = readFileSync(file, "utf8");
  // The person labels the first on the dashboard: read closes it.
  rows.push(dbLabel(`${REPO}/deploy/id_rsa`));
  const listed = ops.list();
  assert.equal(listed.suggestions.find((v) => v.id === first)?.status, "superseded");
  assert.equal(listed.suggestions.find((v) => v.id === second)?.status, "pending");
  // The second labelled between the read and the apply: apply closes it, writing nothing.
  rows.push(dbLabel(`${REPO}/b/id_rsa`, "local-model"));
  const a = ops.apply(second, { via: "agent-tighten", by: "data-plane" });
  assert.equal(!a.applied && a.refused, "covered");
  assert.equal(proposals.getProposal(second)!.status, "superseded");
  assert.equal(readFileSync(file, "utf8"), lawBefore, "no duplicate lock written to policy.yaml");
});

test("provenance and direction: applySuggestion records who did it, never loosens, and a data-plane apply is not the agent's own tightening budget", () => {
  const r = ops.fileFromScan(scanOf([finding("deploy/id_rsa")]));
  const a = ops.apply(r.filed[0]!, { via: "agent-tighten", by: "data-plane" });
  assert.ok(a.applied);
  assert.equal(proposals.getChange(a.changeId)!.via, "agent-tighten");
  assert.equal(proposals.getChange(a.changeId)!.sessionKey, null);
  assert.equal(proposals.tighteningsBy(null), 0, "a scan suggestion applied on the data plane does not spend a session's cap");
  // A suggestion row that would LOOSEN the law (an any-model label on a file
  // nobody labelled, not flagged humanOnly), as a faulty or older scan might
  // have filed it: refused on every applySuggestion via, the law untouched.
  const loose = proposals.fileSuggestion({
    edits: [{ op: "lock-path", path: `${REPO}/notes.txt`, level: "any-model" }] as PolicyEdit[],
    findingKey: `test:loose:${REPO}/notes.txt`,
    suggestion: { source: "workspace", repoRoot: REPO, sentence: "x", evidence: { paths: [], blobs: [], findings: [], historyOnly: false }, impact: { historicalVersions: 0, workingTreeChanges: false, files: [] }, historyOnly: false, rotate: false } as never,
    tightens: [], editsHash: "x", lawHash: "y",
  });
  const lawBefore = readFileSync(file, "utf8");
  const changesBefore = agent.changesList(100).changes.length;
  for (const via of ["agent-tighten", "tighten"] as const) {
    const res = ops.apply(loose.id, { via, by: via === "tighten" ? "human:e2e" : "data-plane" });
    assert.equal(!res.applied && res.refused, "relaxes", via);
    assert.equal(proposals.getProposal(loose.id)!.status, "pending", `${via}: it stays pending`);
  }
  assert.equal(readFileSync(file, "utf8"), lawBefore, "policy.yaml unchanged");
  assert.equal(agent.changesList(100).changes.length, changesBefore, "nothing recorded");
  assert.equal(getCurrentPolicy().pathLabels.has(`${REPO}/notes.txt`), false);
});

test("resolvePolicyProposal on a suggestion: approve applies via proposal; deny dismisses", () => {
  const r = ops.fileFromScan(scanOf([finding("a/id_rsa"), finding("b/id_rsa", { blob: "b".repeat(40) })]));
  const [x, y] = r.filed;
  const ok = agent.resolve(x!, "approved", "human:e2e");
  assert.equal(ok.proposal.status, "approved");
  assert.equal(ok.proposal.kind, "suggestion");
  assert.equal(proposals.getChange(ok.changeId!)!.via, "proposal");
  const no = agent.resolve(y!, "denied", "human:e2e");
  assert.equal(no.proposal.status, "denied");
  assert.equal(ops.fileFromScan(scanOf([finding("b/id_rsa", { blob: "b".repeat(40) })])).counts.dismissed, 1);
});

test("suggestions stay out of the proposal list, the agent's caps and policyExplain; no client names mandu:scan", () => {
  const many = Array.from({ length: 15 }, (_, i) => finding(`k/${i}.pem`, { blob: i.toString(16).padStart(40, "0") }));
  ops.fileFromScan(scanOf(many));
  assert.equal(agent.proposalsList("pending").proposals.length, 0);
  assert.equal(agent.proposalsList("pending", "admin", "suggestion").proposals.length, 15);
  assert.equal(agent.explain().pendingProposals.length, 0);
  assert.equal(proposals.pendingCount(), 0);
  // The agent's own proposals are not blocked by the suggestions.
  for (let i = 0; i < PENDING_CAP_PER_SESSION; i++) {
    const p = agent.propose({ id: i, op: "policyPropose", edits: [{ op: "trust-origin", kind: "url", pattern: `h${i}.example` }], sessionKey: "s1" }, "data");
    assert.equal(p.applied, false);
    assert.ok("proposalId" in p);
  }
  // The admin channel cannot claim the arbiter's own name either.
  const p = agent.propose({ id: 99, op: "policyPropose", edits: [{ op: "trust-origin", kind: "url", pattern: "z.example" }], requestedBy: SCAN_REQUESTER }, "admin");
  assert.ok("proposalId" in p);
  const row = proposals.getProposal((p as { proposalId: string }).proposalId)!;
  assert.equal(row.requestedBy, "human");
  assert.equal(row.kind, "proposal");
});

test("a policy_proposals table from before suggestions gains the columns in place; its rows read as proposals", () => {
  const old = join(dir, "old.db");
  const db = new Database(old);
  db.exec(`CREATE TABLE policy_proposals (id TEXT PRIMARY KEY, edits TEXT NOT NULL, reason TEXT, requested_by TEXT NOT NULL, session_key TEXT,
    relaxes TEXT NOT NULL, tightens TEXT NOT NULL, edits_hash TEXT NOT NULL, law_hash TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL,
    resolved_at INTEGER, resolved_by TEXT, change_id TEXT, superseded_by TEXT)`);
  db.prepare("INSERT INTO policy_proposals VALUES ('pp-000001', '[]', NULL, 'agent:s', 's', '[]', '[]', 'h', 'l', 'pending', 1, NULL, NULL, NULL, NULL)").run();
  db.close();
  const s = new PolicyProposalStore({ dbPath: old });
  const p = s.getProposal("pp-000001")!;
  assert.equal(p.kind, "proposal");
  assert.equal(p.findingKey, null);
  assert.equal(p.suggestion, null);
  const f = s.fileSuggestion({ edits: [], findingKey: "k", suggestion: { source: "git-history", repoRoot: REPO, sentence: "s", evidence: { paths: [], blobs: [], findings: [], historyOnly: true }, impact: { historicalVersions: 0, workingTreeChanges: false, files: [] }, historyOnly: true, rotate: true }, tightens: [], editsHash: "e", lawHash: "l" });
  s.close();
  const again = new PolicyProposalStore({ dbPath: old });
  assert.equal(again.getProposal(f.id)!.kind, "suggestion");
  assert.equal(again.getProposal(f.id)!.suggestion?.repoRoot, REPO);
  again.close();
});

// ── plan 14 §13.4: filing across the two sources ─────────────────────────────

function wsFinding(path: string, over: Partial<SecretWorkspaceFinding> = {}): SecretWorkspaceFinding {
  return { root: REPO, tier: "workspace", repoRoot: REPO, path, detectors: [{ kind: "content-shape", rule: "github-token", line: 1, preview: "ghp_…" }], ...over };
}

function wsScanOf(findings: SecretWorkspaceFinding[], roots = [REPO]): SecretWorkspaceScan {
  return {
    roots: roots.map((root) => ({ root, tier: "workspace" as const })),
    counts: { examined: 10, read: 8, cached: 0, bytes: 100, covered: 1 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, special: 0, depth: 0, worktrees: 0, lines: [] },
    findings, limits: DEFAULT_WORKSPACE_LIMITS, ms: 3,
  };
}

test("§13.4: a file both scans find is ONE suggestion, the history one (filed first); a later workspace scan files nothing", () => {
  const present = new PolicySuggestionOps({ docs, proposals, emit: (e) => events.push(e), exists: () => true, now: () => clock });
  const history = scanOf([finding("config.env.txt", { inHead: true, stillPresent: true })]);
  const workspace = wsScanOf([wsFinding(`${REPO}/config.env.txt`), wsFinding(`${REPO}/deploy/staging.conf`)]);
  const r = present.fileFromScans({ history, workspace }, { home: "/home/u" });
  assert.equal(r.counts.findings, 3);
  assert.equal(r.counts.suggested, 3);
  assert.equal(r.counts.filed, 2);
  assert.equal(r.counts.alreadyPending, 1, "the workspace twin of the history suggestion");
  const bySource = Object.fromEntries(r.suggestions.map((s) => [s.findingKey, s.source]));
  assert.deepEqual(bySource, {
    [`git-history:path:${REPO}/config.env.txt`]: "git-history",
    [`workspace:path:${REPO}/deploy/staging.conf`]: "workspace",
  });
  const ws = r.suggestions.find((s) => s.source === "workspace")!;
  assert.equal(ws.rotate, false);
  assert.equal(ws.sentence, "Make ~/proj/deploy/staging.conf a secret no AI may read");
  assert.deepEqual(r.workspaceScan, { roots: workspace.roots, counts: workspace.counts, capped: workspace.capped, limits: workspace.limits, ms: 3 });
  assert.ok(!("findings" in (r.workspaceScan as object)), "the summary carries no findings");
  assert.ok(r.scan !== null);
  const later = present.fileFromScans({ workspace: wsScanOf([wsFinding(`${REPO}/config.env.txt`)]) });
  assert.equal(later.counts.filed, 0);
  assert.equal(later.counts.alreadyPending, 1, "locked by the pending history suggestion");
  assert.equal(later.scan, null, "no history scan was asked for");
});

test("§13.4: a dismissal blocks both sources; the workspace key blocks itself", () => {
  const present = new PolicySuggestionOps({ docs, proposals, exists: () => true, now: () => clock });
  const h = present.fileFromScans({ history: scanOf([finding("app.conf", { inHead: true, stillPresent: true })]) });
  present.dismiss(h.filed[0]!, "human:e2e");
  const w = present.fileFromScans({ workspace: wsScanOf([wsFinding(`${REPO}/app.conf`)]) });
  assert.equal(w.counts.filed, 0);
  assert.equal(w.counts.dismissed, 1, "a dismissed history suggestion blocks the workspace one");

  const w2 = present.fileFromScans({ workspace: wsScanOf([wsFinding(`${REPO}/other.conf`)]) });
  assert.equal(w2.counts.filed, 1);
  present.dismiss(w2.filed[0]!, "human:e2e");
  const h2 = present.fileFromScans({ history: scanOf([finding("other.conf", { blob: "d".repeat(40), inHead: true, stillPresent: true })]) });
  assert.equal(h2.counts.filed, 0);
  assert.equal(h2.counts.dismissed, 1, "a dismissed workspace suggestion blocks the history one");
  const w3 = present.fileFromScans({ workspace: wsScanOf([wsFinding(`${REPO}/other.conf`)]) });
  assert.equal(w3.counts.dismissed, 1, "and its own key");
});

test(`§13.4: the per-repository cap (${SUGGESTION_CAP_PER_REPO}) counts both sources`, () => {
  const history = scanOf(Array.from({ length: SUGGESTION_CAP_PER_REPO - 2 }, (_, i) => finding(`k/${i}.pem`, { blob: i.toString(16).padStart(40, "0") })));
  const workspace = wsScanOf(Array.from({ length: 5 }, (_, i) => wsFinding(`${REPO}/cfg/${i}.conf`)));
  const r = ops.fileFromScans({ history, workspace });
  assert.equal(r.counts.filed, SUGGESTION_CAP_PER_REPO);
  assert.equal(r.counts.overCap, 3);
  assert.equal(proposals.pendingSuggestionCount(REPO), SUGGESTION_CAP_PER_REPO);
  assert.equal(proposals.listProposals({ status: "pending", kind: "suggestion" }).filter((p) => p.suggestion?.source === "workspace").length, 2, "history filed first");
});

test("§13.4: the answer lists the pending suggestions under a walked root; fileFromScan (history only) answers workspaceScan null", () => {
  const nested = wsFinding("/srv/app/sub/x.conf", { root: "/srv/app", repoRoot: "/srv/app/sub" });
  const r = ops.fileFromScans({ workspace: wsScanOf([nested], ["/srv/app"]) });
  assert.deepEqual(r.suggestions.map((s) => s.repoRoot), ["/srv/app/sub"]);
  const other = ops.fileFromScans({ workspace: wsScanOf([], ["/srv/elsewhere"]) });
  assert.deepEqual(other.suggestions, [], "another root's suggestions are not this answer's");
  const h = ops.fileFromScan(scanOf([finding("deploy/id_rsa")]));
  assert.equal(h.workspaceScan, null);
  assert.equal(h.counts.filed, 1);
});

test("§13.5: suggestPolicy validates sources and includeHome; axis OFF answers workspaceScan null; sources pick the scans", async () => {
  const sdir = mkdtempSync(join(tmpdir(), "mdu-suggest-src-"));
  const home = join(sdir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "app.conf"), `API_TOKEN=${"gh" + "p_" + "Q7wX2mZ9pL4kV8rT".repeat(3)}\n`);
  const mk = (confidentiality: boolean) => new ArbiterServer({
    socketPath: join(sdir, `${confidentiality}.sock`), dbPath: join(sdir, `${confidentiality}.sqlite`), eventDir: join(sdir, `ev-${confidentiality}`),
    log: () => {}, confidentiality, integrity: false, policyPollMs: 0, policyDocument: null,
    workspaceScan: { env: {}, discovery: { installEnv: {}, selfDir: null } },
  });
  const on = mk(true);
  try {
    const ask = (extra: Record<string, unknown>) => on.suggestPolicyOp({ id: 1, op: "suggestPolicy", roots: [proj], home, ...extra } as never);
    for (const sources of [[], ["git-history", "git-history"], ["nope"], "workspace", ["workspace", "git-history", "workspace"]]) {
      const r = await ask({ sources });
      assert.equal(r.ok, false, JSON.stringify(sources));
      assert.match((r as { error: string }).error, /sources must list/);
    }
    const noHome = await on.suggestPolicyOp({ id: 2, op: "suggestPolicy", roots: [proj], includeHome: true });
    assert.equal(noHome.ok, false);
    assert.match((noHome as { error: string }).error, /includeHome needs home/);
    const notBool = await ask({ includeHome: "yes" });
    assert.equal(notBool.ok, false);
    const ws = await ask({ sources: ["workspace"] });
    assert.equal(ws.ok, true);
    const res = (ws as { result: SuggestPolicyResult }).result;
    assert.equal(res.scan, null, "no history scan was asked for");
    assert.ok(res.workspaceScan !== null);
    assert.equal(res.workspaceScan!.roots[0]!.tier, "workspace");
    assert.equal(res.counts.filed, 1);
    assert.equal(res.suggestions[0]!.source, "workspace");
    assert.ok(!JSON.stringify(res).includes("Q7wX2mZ9"), "no value in the reply");
    const hist = await ask({ sources: ["git-history"] });
    assert.equal((hist as { result: SuggestPolicyResult }).result.workspaceScan, null);
    const both = await ask({ includeHome: true });
    const bres = (both as { result: SuggestPolicyResult }).result;
    assert.deepEqual(bres.workspaceScan!.roots.map((r) => r.tier), ["workspace", "home"]);
    assert.equal(bres.counts.alreadyPending, 1, "the same file again");
  } finally {
    await on.close();
  }
  const off = mk(false);
  try {
    const r = await off.suggestPolicyOp({ id: 3, op: "suggestPolicy", roots: [proj], home });
    assert.deepEqual((r as { result: SuggestPolicyResult }).result.workspaceScan, null);
    assert.equal((r as { result: SuggestPolicyResult }).result.axis, false);
  } finally {
    await off.close();
    rmSync(sdir, { recursive: true, force: true });
  }
});

test("§5.5: earlierScanAt — every root under a finished root, the stalest time; a sibling with a common prefix is not under", () => {
  const done = new Map<string, number>([["/h/proj", 100], ["/h/proj/sub", 300], ["/h/other/", 50]]);
  assert.equal(earlierScanAt(done, ["/h/proj"]), 100);
  assert.equal(earlierScanAt(done, ["/h/proj/sub/deep"]), 300, "the newest finished root holding it");
  assert.equal(earlierScanAt(done, ["/h/proj/src"]), 100);
  assert.equal(earlierScanAt(done, ["/h/other/x"]), 50);
  assert.equal(earlierScanAt(done, ["/h/proj-two"]), null);
  assert.equal(earlierScanAt(done, ["/h"]), null, "a folder above a scanned one was not scanned");
  assert.equal(earlierScanAt(done, ["/h/proj/sub", "/h/other/y"]), 50, "the stalest root's time");
  assert.equal(earlierScanAt(done, ["/h/proj", "/elsewhere"]), null, "every root must have one");
  assert.equal(earlierScanAt(done, []), null);
  assert.equal(earlierScanAt(new Map(), ["/h/proj"]), null);
});

test("§5.5: answerFromEarlier — validated; a first scan is waited for; after a finished one (every source) the op answers at once from it", async () => {
  const sdir = mkdtempSync(join(tmpdir(), "mdu-suggest-earlier-"));
  const home = join(sdir, "home");
  const proj = join(home, "proj");
  const other = join(home, "other");
  mkdirSync(proj, { recursive: true });
  mkdirSync(other, { recursive: true });
  writeFileSync(join(proj, "app.conf"), `API_TOKEN=${"gh" + "p_" + "Q7wX2mZ9pL4kV8rT".repeat(3)}\n`);
  // The history scan's git runner (the server's `historyScan` seam): real
  // git, but while the test HOLDS it every call waits for the release, so a
  // background scan is provably still running when the op answers. Without
  // the hold the test raced the scan: the op's zero budget is a timer, and a
  // scan with little to do (a folder that is no work tree, or missing) can
  // end before it fires, and the op then answers with that fresh result
  // (`running: false`; seen on a CI runner, 2026-10-04).
  let held: { reached: () => void; gate: Promise<void>; open: () => void } | null = null;
  const git: HistoryGitRunner = async (args, o) => {
    const h = held;
    if (h !== null) { h.reached(); await h.gate; }
    return defaultHistoryGitRunner(args, o);
  };
  /** Hold the next scan at its first git call: `reached` resolves once a
   *  scan waits there, `release` lets it go on. */
  const hold = (): { reached: Promise<void>; release: () => void } => {
    let open!: () => void;
    let reached!: () => void;
    const gate = new Promise<void>((res) => { open = res; });
    const waiting = new Promise<void>((res) => { reached = res; });
    held = { reached, gate, open };
    return { reached: waiting, release: unhold };
  };
  /** Let the held scan (if any) go on. */
  const unhold = (): void => { const h = held; held = null; h?.open(); };
  /** An op that waited for a held scan would never answer: fail, not hang.
   *  (The timer is ref'd: a held scan holds no handle, and the op's own
   *  zero-budget timer is unref'd.) */
  const promptly = async <T,>(p: Promise<T>): Promise<T> => {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([p, new Promise<never>((_, rej) => {
        timer = setTimeout(() => rej(new Error("the op waited for its held scan instead of answering from the earlier one")), 20_000);
      })]);
    } finally {
      clearTimeout(timer);
    }
  };
  const on = new ArbiterServer({
    socketPath: join(sdir, "a.sock"), dbPath: join(sdir, "a.sqlite"), eventDir: join(sdir, "ev"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: null,
    historyScan: { git },
    workspaceScan: { env: {}, discovery: { installEnv: {}, selfDir: null } },
  });
  const ask = async (roots: string[], extra: Record<string, unknown>): Promise<SuggestPolicyResult> => {
    const r = await on.suggestPolicyOp({ id: 1, op: "suggestPolicy", roots, home, ...extra } as never);
    assert.equal(r.ok, true, JSON.stringify(r));
    return (r as { result: SuggestPolicyResult }).result;
  };
  /** The background scan is over when a call without a budget runs (it
   *  refuses while one runs). */
  const settle = async (): Promise<SuggestPolicyResult> => {
    for (let i = 0; i < 600; i++) {
      const r = await on.suggestPolicyOp({ id: 9, op: "suggestPolicy", roots: [proj], home } as never);
      if (r.ok) return (r as { result: SuggestPolicyResult }).result;
      await new Promise((res) => setTimeout(res, 50));
    }
    throw new Error("the background scan never ended");
  };
  try {
    const bad = await on.suggestPolicyOp({ id: 1, op: "suggestPolicy", roots: [proj], home, answerFromEarlier: "yes" } as never);
    assert.equal(bad.ok, false);
    assert.match((bad as { error: string }).error, /answerFromEarlier must be a boolean/);
    // No scan finished yet: the budget is honoured; the scan ends inside it.
    const first = await ask([proj], { waitMs: 60_000, answerFromEarlier: true });
    assert.equal(first.running, false);
    assert.equal(typeof first.lastScanAt, "number");
    assert.equal(first.suggestions.length, 1);
    // A finished scan of every source covers proj and what lies under it:
    // the next asks answer at once, from what it left, while a scan runs.
    // The new scan is held, so the op cannot have waited for it: it answers
    // while that scan still runs, from the earlier one.
    const h2 = hold();
    const second = await promptly(ask([proj], { waitMs: 60_000, answerFromEarlier: true }));
    await h2.reached;
    assert.equal(second.running, true, "answered before its scan ended");
    assert.equal(second.lastScanAt, first.lastScanAt, "the earlier scan's time");
    assert.deepEqual(second.suggestions.map((s) => s.id), first.suggestions.map((s) => s.id));
    assert.deepEqual([second.scan, second.workspaceScan, second.filed], [null, null, []]);
    const busy = await on.suggestPolicyOp({ id: 8, op: "suggestPolicy", roots: [proj], home } as never);
    assert.equal(busy.ok, false, "the scan the op started still runs after it answered");
    h2.release();
    const third = await settle();
    assert.equal(third.running, false);
    assert.ok(third.lastScanAt! >= first.lastScanAt!, "the background scan recorded its own time");
    const h3 = hold();
    const under = await promptly(ask([join(proj, "src")], { waitMs: 60_000, answerFromEarlier: true }));
    await h3.reached;
    assert.equal(under.running, true, "a folder under a scanned root");
    assert.equal(under.lastScanAt, third.lastScanAt, "answered from proj's finished scan");
    h3.release();
    await settle();
    // Without the flag the budget stands (an older launcher, the dashboard).
    const plain = await ask([proj], { waitMs: 60_000 });
    assert.equal(plain.running, false);
    // A scan of some sources only does not count as one; another root has none.
    const partial = await ask([other], { sources: ["workspace"] });
    assert.equal(partial.lastScanAt, null);
    const fresh = await ask([other], { waitMs: 60_000, answerFromEarlier: true });
    assert.equal(fresh.running, false, "no finished scan of every source there: waited");
    assert.equal(typeof fresh.lastScanAt, "number");
  } finally {
    unhold();
    await on.close();
    rmSync(sdir, { recursive: true, force: true });
  }
});

test("§14.4: model suggestions share the scans' dedup and cap, filed after them; applying a folder rule supersedes what it grouped", () => {
  const model = (path: string, covers: string[] = []) => ({
    findingKey: `model-names:path:${path}`, source: "model-names" as const, repoRoot: REPO,
    edits: [{ op: "lock-path" as const, path, level: "no-model" as const }],
    sentence: `Make ${path} a secret no AI may read`,
    evidence: { paths: [path.slice(REPO.length + 1)], blobs: [], findings: [], historyOnly: false },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: [path.slice(REPO.length + 1)] },
    historyOnly: false, rotate: false,
    model: { endpoint: "cloud", level: "no-model" as const, reason: "legal" as const, reasonWords: "looks like legal documents", candidate: "folder" as const, files: 2, covers },
  });
  // A pending workspace suggestion on the same file blocks the model's.
  const w = ops.fileFromScans({ workspace: wsScanOf([wsFinding(`${REPO}/legal/q3.conf`)]) });
  assert.equal(w.counts.filed, 1);
  const same = ops.fileModelSuggestions([model(`${REPO}/legal/q3.conf`)]);
  assert.deepEqual(same.counts, { filed: 0, alreadyPending: 1, dismissed: 0, overCap: 0, superseded: 0 });
  // A folder rule groups it and files; the source rides on the view.
  const folder = ops.fileModelSuggestions([model(`${REPO}/legal`, [w.filed[0]!])]);
  assert.equal(folder.counts.filed, 1);
  const v = ops.list("pending").suggestions.find((s) => s.id === folder.filed[0])!;
  assert.equal(v.source, "model-names");
  assert.equal(v.requestedBy, SCAN_REQUESTER);
  assert.deepEqual(v.model?.covers, [w.filed[0]]);
  // Filed again: the key blocks it.
  assert.equal(ops.fileModelSuggestions([model(`${REPO}/legal`)]).counts.alreadyPending, 1);
  // Applying it supersedes the grouped workspace suggestion, linked to it.
  const applied = ops.apply(folder.filed[0]!, { via: "agent-tighten", by: "data-plane" });
  assert.equal(applied.applied, true);
  const closed = proposals.getProposal(w.filed[0]!)!;
  assert.equal(closed.status, "superseded");
  assert.equal(closed.supersededBy, folder.filed[0]);
  // The shared cap: a full repository files no model suggestion.
  ops.fileFromScans({ workspace: wsScanOf(Array.from({ length: SUGGESTION_CAP_PER_REPO }, (_, i) => wsFinding(`${REPO}/cfg/${i}.conf`))) });
  assert.equal(ops.fileModelSuggestions([model(`${REPO}/finance`)]).counts.overCap, 1);
});
