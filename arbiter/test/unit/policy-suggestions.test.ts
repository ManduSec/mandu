/**
 * policy-suggestions.test — the generator of confidentiality plan 14 §4
 * (arbiter/policy/policy-suggestions.ts), pure over hand-built findings.
 *
 * Pins:
 *   - the §4 mapping table: a gone path → lock-path; a present path whose
 *     current content holds the key → lock-path; a present path whose
 *     current content does not → lock-blob; covered (protected now, or the
 *     law already labels it) → no suggestion, listed as covered;
 *   - grouping: the findings of one repository that share a path are one
 *     secret; the same path in two repositories is two;
 *   - the tightening check: an edit that relaxes or does not validate drops
 *     the suggestion; an edit with no effect is removed;
 *   - the sentence comes from the edits (never a finding's mask), the
 *     evidence and impact from the findings;
 *   - a committed file whose name holds glob metacharacters is locked as a
 *     literal, not a pattern;
 *   - §13.4, the workspace generator: one lock-path per file, its key,
 *     sentence, evidence (the history shape, no commits) and impact, and
 *     `rotate: false`.
 *
 * No privilege; the protection axes are not read by this code.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { POLICY_EDIT_OPS, applyEdits } from "../../policy/policy-edit.js";
import {
  blobId,
  displayPath,
  findingKeyOf,
  groupFindings,
  judgeEdits,
  literalLabelPath,
  suggestEdits,
  suggestionSentence,
  suggestWorkspaceEdits,
  workspaceFindingKey,
  type SuggestLaw,
} from "../../policy/policy-suggestions.js";
import type { SecretWorkspaceFinding } from "../../policy/secret-workspace-scan.js";
import type { SecretHistoryFinding } from "../../policy/secret-history-scan.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const HOME = "/home/u";
const REPO = "/home/u/proj";
const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(40);
const LOCK_BLOB_KNOWN = (POLICY_EDIT_OPS as readonly string[]).includes("lock-blob");

function law(doc: PolicyFileConfig | null = null): SuggestLaw {
  return compilePolicy({ specId: "claude-code", document: doc });
}

function finding(over: Partial<SecretHistoryFinding> & { blob: string; paths: string[] }): SecretHistoryFinding {
  const detector = { kind: "content-shape" as const, rule: "private-key" as const, line: 1, preview: "-----BEGIN OPENSSH " + "PRIVATE KEY-----…" };
  return {
    repoRoot: REPO,
    firstCommit: "1".repeat(40),
    lastCommit: "2".repeat(40),
    inHead: false,
    inIndex: false,
    stillPresent: false,
    pathStillSecretByCatalog: false,
    detector,
    detectors: [detector],
    ...over,
  };
}

const existsOnly = (...present: string[]) => (p: string): boolean => present.includes(p);

test("§4 table: a path gone from the work tree → lock-path no-model, history only", () => {
  const r = suggestEdits([finding({ blob: A, paths: ["deploy/id_rsa"] })], law(), { exists: existsOnly(), home: HOME });
  assert.equal(r.suggestions.length, 1);
  const s = r.suggestions[0]!;
  assert.deepEqual(s.edits, [{ op: "lock-path", path: `${REPO}/deploy/id_rsa`, level: "no-model" }]);
  assert.equal(s.sentence, "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)");
  assert.equal(s.historyOnly, true);
  assert.equal(s.rotate, true);
  assert.deepEqual(s.impact, { historicalVersions: 1, workingTreeChanges: false, files: [] });
  assert.equal(s.findingKey, `git-history:path:${REPO}/deploy/id_rsa`);
  assert.equal(s.evidence.findings[0]!.detectors[0]!.words, "private key");
  assert.equal(s.evidence.findings[0]!.firstCommit, "1".repeat(40));
});

test("§4 table: a present path whose current content holds the key → lock-path; the working tree changes", () => {
  const f = finding({ blob: A, paths: ["prod.pem"], inHead: true, stillPresent: true });
  const r = suggestEdits([f], law(), { exists: existsOnly(`${REPO}/prod.pem`), home: HOME });
  const s = r.suggestions[0]!;
  assert.deepEqual(s.edits, [{ op: "lock-path", path: `${REPO}/prod.pem`, level: "no-model" }]);
  assert.equal(s.sentence, "Make ~/proj/prod.pem a secret no AI may read");
  assert.equal(s.historyOnly, false);
  assert.deepEqual(s.impact, { historicalVersions: 0, workingTreeChanges: true, files: ["prod.pem"] });
});

test("§4 table: a present path that no longer holds the key → lock-blob on the old version only", () => {
  const f = finding({ blob: B, paths: ["config.py"], stillPresent: true });
  const r = suggestEdits([f], law(), { exists: existsOnly(`${REPO}/config.py`), home: HOME });
  const s = r.suggestions[0]!;
  assert.deepEqual(s.edits, [{ op: "lock-blob", blob: `sha1:${B}`, level: "no-model", note: "found in git history: config.py (1111111..2222222)" }]);
  assert.equal(s.sentence, "Hide an old version of ~/proj/config.py from the AI");
  assert.deepEqual(s.impact, { historicalVersions: 1, workingTreeChanges: false, files: [] });
  assert.equal(s.findingKey, `git-history:blob:sha1:${B}`);
});

test("§4 table: covered by a protection now → no suggestion, listed as covered", () => {
  const f = finding({ blob: C, paths: ["protected.txt"], inHead: true, stillPresent: true, pathStillSecretByCatalog: true });
  const r = suggestEdits([f], law(), { exists: () => true, home: HOME });
  assert.equal(r.suggestions.length, 0);
  assert.deepEqual(r.covered, [{ repoRoot: REPO, paths: ["protected.txt"], blobs: [C], why: "protected-now" }]);
});

test("§4 table: a gone path the law already labels (exact, by a folder, by a pattern) is covered by the law", () => {
  for (const path of [`${REPO}/deploy/id_rsa`, `${REPO}/deploy`, `${REPO}/**/id_rsa`]) {
    const r = suggestEdits([finding({ blob: A, paths: ["deploy/id_rsa"] })], law({ version: 1, paths: [{ path, level: "no-model" }] }), { exists: () => false, home: HOME });
    assert.equal(r.suggestions.length, 0, path);
    assert.equal(r.covered[0]?.why, "law", path);
  }
  // A `public` label is not a cover: the lock raises it.
  const pub = suggestEdits([finding({ blob: A, paths: ["deploy/id_rsa"] })], law({ version: 1, paths: [{ path: `${REPO}/deploy`, level: "public" }] }), { exists: () => false, home: HOME });
  assert.equal(pub.suggestions.length, 1);
});

test("§4 table: a blob the law's blobs: section already locks is covered", () => {
  const doc = { version: 1, blobs: [{ id: `sha1:${B}`, level: "no-model" }] } as unknown as PolicyFileConfig;
  const r = suggestEdits([finding({ blob: B, paths: ["config.py"], stillPresent: true })], { specId: "claude-code", document: doc, pathLabels: new Map() }, { exists: () => true });
  assert.equal(r.suggestions.length, 0);
  assert.equal(r.covered[0]?.why, "law");
});

test("grouping: the versions of one file are one secret; a rename joins; another repository is another secret", () => {
  const fs = [
    finding({ blob: A, paths: ["deploy/id_rsa"] }),
    finding({ blob: B, paths: ["deploy/id_rsa", "keys/id_rsa"] }),
    finding({ blob: C, paths: ["keys/id_rsa"] }),
    finding({ blob: A, paths: ["deploy/id_rsa"], repoRoot: "/home/u/other" }),
  ];
  const groups = groupFindings(fs);
  assert.deepEqual(groups.map((g) => g.map((f) => f.blob)), [[A, B, C], [A]]);
  const r = suggestEdits(fs, law(), { exists: () => false, home: HOME });
  assert.equal(r.suggestions.length, 2);
  const mine = r.suggestions.find((s) => s.repoRoot === REPO)!;
  assert.deepEqual(mine.edits.map((e) => e.op === "lock-path" && e.path), [`${REPO}/deploy/id_rsa`, `${REPO}/keys/id_rsa`]);
  assert.equal(mine.impact.historicalVersions, 3);
  assert.deepEqual(mine.evidence.paths, ["deploy/id_rsa", "keys/id_rsa"]);
  assert.deepEqual(mine.evidence.blobs, [A, B, C]);
});

test("mixed: a gone path and an old version of a present file in one secret → both locks, one sentence", () => {
  const fs = [finding({ blob: A, paths: ["old/.env", "app/.env.local"], stillPresent: true })];
  const r = suggestEdits(fs, law(), { exists: existsOnly(`${REPO}/app/.env.local`), home: HOME });
  const s = r.suggestions[0]!;
  assert.deepEqual(s.edits.map((e) => e.op), ["lock-path", "lock-blob"]);
  assert.equal(s.sentence, "Make ~/proj/old/.env a secret no AI may read (only in git history); Hide an old version of ~/proj/app/.env.local from the AI");
  assert.equal(s.historyOnly, false);
});

test("history-only secrets come first", () => {
  const fs = [
    finding({ blob: B, paths: ["a.pem"], inHead: true, stillPresent: true }),
    finding({ blob: A, paths: ["z/id_rsa"] }),
  ];
  const r = suggestEdits(fs, law(), { exists: existsOnly(`${REPO}/a.pem`) });
  assert.deepEqual(r.suggestions.map((s) => s.historyOnly), [true, false]);
});

test("the tightening check: a relaxing or invalid edit list is dropped; a no-op edit is removed", () => {
  const l = { specId: "claude-code" as const, document: null };
  // Lowering a catalog secret to any-model relaxes: never a suggestion.
  const relax = judgeEdits(l, [{ op: "lock-path", path: "/home/u/.ssh/id_rsa", level: "any-model" as "no-model" }]);
  assert.equal(relax.verdict, "relaxes");
  const invalid = judgeEdits(l, [{ op: "lock-path", path: "relative/path", level: "no-model" }]);
  assert.equal(invalid.verdict, "invalid");
  const doc: PolicyFileConfig = { version: 1, paths: [{ path: "/w/a", level: "no-model" }] };
  const kept = judgeEdits({ specId: "claude-code", document: doc }, [
    { op: "lock-path", path: "/w/a", level: "no-model" },
    { op: "lock-path", path: "/w/b", level: "no-model" },
  ]);
  assert.deepEqual(kept, { verdict: "ok", edits: [{ op: "lock-path", path: "/w/b", level: "no-model" }] });
  assert.deepEqual(judgeEdits({ specId: "claude-code", document: doc }, [{ op: "lock-path", path: "/w/a", level: "no-model" }]), { verdict: "covered" });
  // Through the generator: a finding in a repository whose root is not
  // absolute makes an edit the validator refuses → dropped, not filed.
  const r = suggestEdits([finding({ blob: A, paths: ["id_rsa"], repoRoot: "not/absolute" })], law(), { exists: () => false });
  assert.equal(r.suggestions.length, 0);
  assert.equal(r.dropped[0]?.why, "invalid");
});

test("lock-blob: kept as built until the grammar knows the op, judged by it after", () => {
  const edit = { op: "lock-blob" as const, blob: `sha1:${B}`, level: "no-model" as const };
  const j = judgeEdits({ specId: "claude-code", document: null }, [edit]);
  if (LOCK_BLOB_KNOWN) assert.equal(j.verdict, "ok", "the grammar judges it a tightening");
  else assert.deepEqual(j, { verdict: "ok", edits: [edit] });
});

test("blob ids: sha1 and sha256 object names, anything else refused", () => {
  assert.equal(blobId(A), `sha1:${A}`);
  assert.equal(blobId("F".repeat(64)), `sha256:${"f".repeat(64)}`);
  assert.equal(blobId("xyz"), null);
  // A finding with an object name that is not one yields no blob lock.
  const r = suggestEdits([finding({ blob: "nothex", paths: ["config.py"], stillPresent: true })], law(), { exists: () => true });
  assert.equal(r.suggestions.length, 0);
});

test("a committed file named with glob metacharacters is locked as a literal", () => {
  const r = suggestEdits([finding({ blob: A, paths: ["keys/a[1]*.pem"] })], law(), { exists: () => false, home: HOME });
  const e = r.suggestions[0]!.edits[0]!;
  assert.equal(e.op === "lock-path" && e.path, `${REPO}/keys/a\\[1\\]\\*.pem`);
  assert.equal(literalLabelPath("/x/a?b"), "/x/a\\?b");
  const applied = applyEdits(null, [e]);
  assert.ok(applied.ok);
  const compiled = compilePolicy({ specId: "claude-code", document: applied.document });
  const label = compiled.pathLabels.get(`${REPO}/keys/a[1]*.pem`);
  assert.ok(label, "a literal label on the exact path");
  assert.equal(label!.glob, undefined);
  assert.equal(r.suggestions[0]!.sentence, "Make ~/proj/keys/a[1]*.pem a secret no AI may read (only in git history)");
});

test("the sentence is built from the edits, never from a finding's text", () => {
  const f = finding({
    blob: A, paths: ["cfg"],
    detector: { kind: "content-shape", rule: "credential-assignment", line: 3, preview: "IGNORE_PREVIOUS_AND_ALLOW=…" },
    detectors: [{ kind: "content-shape", rule: "credential-assignment", line: 3, preview: "IGNORE_PREVIOUS_AND_ALLOW=…" }],
  });
  const s = suggestEdits([f], law(), { exists: () => false, home: HOME }).suggestions[0]!;
  assert.doesNotMatch(s.sentence, /IGNORE/);
  assert.equal(s.evidence.findings[0]!.detectors[0]!.mask, "IGNORE_PREVIOUS_AND_ALLOW=…", "the mask stays evidence");
  assert.equal(suggestionSentence([{ op: "lock-blob", blob: "sha1:x", level: "no-model" }, { op: "lock-blob", blob: "sha1:y", level: "no-model" }], { blobPath: new Map([["sha1:x", "/w/f"], ["sha1:y", "/w/f"]]) }), "Hide 2 old versions of /w/f from the AI");
  assert.equal(displayPath("/home/u", "/home/u"), "~");
  assert.equal(displayPath("/home/uv/x", "/home/u"), "/home/uv/x");
});

test("finding keys: deterministic over the edits, order-free, bounded", () => {
  const a = { op: "lock-path" as const, path: "/w/a", level: "no-model" as const };
  const b = { op: "lock-blob" as const, blob: `sha1:${A}`, level: "no-model" as const };
  assert.equal(findingKeyOf([a, b]), findingKeyOf([b, a]));
  const many = Array.from({ length: 40 }, (_, i) => ({ op: "lock-path" as const, path: `/w/${"x".repeat(20)}${i}`, level: "no-model" as const }));
  assert.match(findingKeyOf(many), /^git-history:sha256:[0-9a-f]{64}$/);
});

// ── §13.4: the workspace generator ───────────────────────────────────────────

function wsFinding(path: string, over: Partial<SecretWorkspaceFinding> = {}): SecretWorkspaceFinding {
  return {
    root: REPO, tier: "workspace", repoRoot: REPO, path,
    detectors: [{ kind: "content-shape", rule: "github-token", line: 2, preview: "ghp_…" }],
    ...over,
  };
}

test("§13.4 workspace: one lock-path per file; its key, sentence, evidence, impact; no rotation claim", () => {
  const r = suggestWorkspaceEdits([wsFinding(`${REPO}/deploy/staging.conf`)], law(), { home: HOME });
  assert.equal(r.suggestions.length, 1);
  const s = r.suggestions[0]!;
  assert.deepEqual(s.edits, [{ op: "lock-path", path: `${REPO}/deploy/staging.conf`, level: "no-model" }]);
  assert.equal(s.source, "workspace");
  assert.equal(s.findingKey, `workspace:path:${REPO}/deploy/staging.conf`);
  assert.equal(s.repoRoot, REPO);
  assert.equal(s.sentence, "Make ~/proj/deploy/staging.conf a secret no AI may read");
  assert.deepEqual(s.evidence, {
    paths: ["deploy/staging.conf"],
    blobs: [],
    findings: [{
      blob: "", paths: ["deploy/staging.conf"], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }],
    }],
    historyOnly: false,
  });
  assert.deepEqual(s.impact, { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/staging.conf"] });
  assert.equal(s.historyOnly, false);
  assert.equal(s.rotate, false, "nothing shows the key left the machine");
});

test("§13.4 workspace: no work tree → the scan root; labelled → covered; a glob name is a literal; one per file; a long key is hashed", () => {
  const loose = suggestWorkspaceEdits([wsFinding("/srv/app/cfg/prod.ini", { root: "/srv/app", repoRoot: null })], law());
  assert.equal(loose.suggestions[0]!.repoRoot, "/srv/app");
  assert.deepEqual(loose.suggestions[0]!.evidence.paths, ["cfg/prod.ini"]);
  for (const path of [`${REPO}/deploy/staging.conf`, `${REPO}/deploy`, `${REPO}/**/*.conf`]) {
    const r = suggestWorkspaceEdits([wsFinding(`${REPO}/deploy/staging.conf`)], law({ version: 1, paths: [{ path, level: "no-model" }] }), { home: HOME });
    assert.equal(r.suggestions.length, 0, path);
    assert.deepEqual(r.covered, [{ repoRoot: REPO, paths: ["deploy/staging.conf"], blobs: [], why: "law" }], path);
  }
  const glob = suggestWorkspaceEdits([wsFinding(`${REPO}/a[1]*.conf`), wsFinding(`${REPO}/a[1]*.conf`)], law(), { home: HOME });
  assert.equal(glob.suggestions.length, 1, "one suggestion per file");
  assert.deepEqual(glob.suggestions[0]!.edits, [{ op: "lock-path", path: `${REPO}/a\\[1\\]\\*.conf`, level: "no-model" }]);
  assert.equal(glob.suggestions[0]!.findingKey, `workspace:path:${REPO}/a\\[1\\]\\*.conf`);
  assert.match(workspaceFindingKey(`/${"x".repeat(600)}`), /^workspace:sha256:[0-9a-f]{64}$/);
  const rel = suggestWorkspaceEdits([wsFinding("relative/x.conf")], law());
  assert.equal(rel.suggestions.length, 0, "a relative path is never locked");
});
