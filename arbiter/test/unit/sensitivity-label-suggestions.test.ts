/**
 * sensitivity-label-suggestions.test — S4 end to end inside the arbiter's
 * units (confidentiality plan 14 §14.1, 4a): the label read inside the
 * workspace walk (secret-workspace-scan.ts), the generator
 * (`suggestLabelEdits`), and filing and applying (policy-suggestion-ops.ts)
 * over a real policy file and proposal store.
 *
 * Pins:
 *   - the walk: no Office file opened in mode `off`; `count` counts labelled
 *     and unmapped files (ids with file counts, at most 50); `mapped` finds
 *     the labelled files; a covered file is never opened; an Office file is
 *     never text-read (a token in it is no S2 finding); both tiers (the home
 *     tier reads Office files without a name hint); encrypted, bomb, Zip64
 *     counted; the label budgets (files, bytes) and their plain lines; the
 *     cache (a hit, a miss on a changed file); `readText: false`;
 *   - the generator: the strictest mapped level; `public` and unmapped
 *     suggest nothing; a site-bound mapping ignores another tenant; a
 *     no-model lock goes through the tightening check; a lower one is
 *     `humanOnly`; a law-covered path is covered; a path with its own label
 *     is not changed below no-model; the sentence uses the MAPPING's name;
 *     no file text anywhere;
 *   - filing and applying: a mapped no-model label files one lock-path that
 *     the data plane applies; a humanOnly one is refused on the data plane
 *     and applied by a person (admin resolve), never over a file protected
 *     now; the stricter suggestion replaces a weaker pending one for the
 *     same file (a history key found later; a raised mapping), a dismissal
 *     still blocks.
 *
 * No privilege; the protection axes are not read by this code.
 */
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { compilePolicy, getCurrentPolicy, resetCurrentPolicyForTests, swapCurrentPolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { PolicyDocumentStore } from "../../policy/policy-document-store.js";
import { PolicyProposalStore, SCAN_REQUESTER } from "../../policy/policy-proposals.js";
import { loadPolicyFileStrict } from "../../policy/policy-file-validate.js";
import { labelFindingKey, suggestLabelEdits, type Suggestion } from "../../policy/policy-suggestions.js";
import { contentsFindingKey } from "../../policy/policy-model.js";
import { DEFAULT_HISTORY_LIMITS, type SecretHistoryFinding, type SecretHistoryScan } from "../../policy/secret-history-scan.js";
import {
  DEFAULT_WORKSPACE_LIMITS, WorkspaceScanCache, defaultWorkspaceFs, scanSecretWorkspace,
  type LabelCacheEntry, type SecretWorkspaceScan, type WorkspaceScanFs,
} from "../../policy/secret-workspace-scan.js";
import { effectiveLabelMapping, mapLabel, type LabelMappingEntry, type SensitivityLabelFinding } from "../../policy/sensitivity-labels.js";
import { PolicySuggestionOps } from "../../ipc/policy-suggestion-ops.js";
import { bombLabelInfo, buildEncryptedContainer, buildOfficeFile } from "../helpers/office-zip.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const CONF = "7c7c7c7c-1111-4222-8333-444455556666";
const GEN = "1e4f7c2a-3b5d-4e6f-8a9b-0c1d2e3f4a5b";
const UNMAPPED = "2b2b2b2b-1111-4222-8333-444455556666";
const TENANT = "5b3c2d4e-1111-4222-8333-444455556666";
const OTHER_TENANT = "0a0b0c0d-1111-4222-8333-999988887777";
const BODY = "CANARY-BODY-3d9e";
const NAME = "CANARY-NAME-8c1f";
const alnum = (n: number): string => Array.from({ length: n }, (_, i) => "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"[(i * 7 + 3) % 57]).join("");
const TOKEN = "gh" + "p_" + alnum(36);

const MAPPING: LabelMappingEntry[] = effectiveLabelMapping([
  { id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" },
  { id: CONF, name: "Confidential", level: "any-model" },
  { id: GEN, name: "General", level: "public" },
]);
const isMapped = (l: { id: string; site: string | null }): boolean => mapLabel(l, MAPPING) !== null;

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); resetCurrentPolicyForTests("claude-code"); });

function tree(): { root: string; home: string; files: Record<string, string> } {
  const home = mkdtempSync(join(tmpdir(), "mandu-labels-home-"));
  dirs.push(home);
  const root = join(home, "proj");
  mkdirSync(join(root, "board"), { recursive: true });
  mkdirSync(join(root, ".git"));
  const files: Record<string, string> = {
    hc: join(root, "board", "q3-board.docx"),
    conf: join(root, "budget.xlsx"),
    gen: join(root, "notes.pptx"),
    unmapped: join(root, "plan.docm"),
    unmapped2: join(root, "plan2.docx"),
    otherTenant: join(root, "partner.docx"),
    disabled: join(root, "draft.docx"),
    none: join(root, "plain.docx"),
    enc: join(root, "sealed.docx"),
    bomb: join(root, "bomb.docx"),
    zip64: join(root, "big.xlsx"),
    covered: join(root, "covered.docx"),
    text: join(root, "deploy.conf"),
    homeDoc: join(home, "Documents-offer.docx"),
  };
  writeFileSync(files.hc!, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }, { id: GEN, site: TENANT }], body: `${BODY} ${TOKEN}` }));
  writeFileSync(files.conf!, buildOfficeFile({ custom: [{ id: CONF, site: TENANT, name: NAME }], body: BODY }));
  writeFileSync(files.gen!, buildOfficeFile({ labelInfo: [{ id: GEN }], body: BODY }));
  writeFileSync(files.unmapped!, buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY }));
  writeFileSync(files.unmapped2!, buildOfficeFile({ labelInfo: [{ id: UNMAPPED, site: TENANT }], body: BODY }));
  writeFileSync(files.otherTenant!, buildOfficeFile({ labelInfo: [{ id: HC, site: OTHER_TENANT }], body: BODY }));
  writeFileSync(files.disabled!, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT, enabled: false }], body: BODY }));
  writeFileSync(files.none!, buildOfficeFile({ body: BODY }));
  writeFileSync(files.enc!, buildEncryptedContainer());
  writeFileSync(files.bomb!, buildOfficeFile({ labelInfoRaw: bombLabelInfo(8) }));
  writeFileSync(files.zip64!, buildOfficeFile({ labelInfo: [{ id: HC }], zip: { zip64Markers: true } }));
  writeFileSync(files.covered!, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], body: BODY }));
  writeFileSync(files.text!, `API_TOKEN=${TOKEN}\n`);
  writeFileSync(files.homeDoc!, buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], body: BODY }));
  return { root, home, files };
}

/** The real filesystem, recording every Office file the label read opens. */
function recordingFs(opened: string[]): WorkspaceScanFs {
  return {
    ...defaultWorkspaceFs,
    readLabels: (p, caps) => { opened.push(p); return defaultWorkspaceFs.readLabels!(p, caps); },
    readRegular: (p, caps) => { opened.push(`text:${p}`); return defaultWorkspaceFs.readRegular(p, caps); },
  };
}

test("the walk, mode off: no Office file is opened, and none is text-read", async () => {
  const { root, home, files } = tree();
  const opened: string[] = [];
  const scan = await scanSecretWorkspace([root], { home, fs: recordingFs(opened), yieldNow: async () => {}, sensitivityLabels: { mode: "off", isMapped } });
  assert.deepEqual(opened, [`text:${files.text}`]);
  assert.equal(scan.labels?.mode, "off");
  assert.equal(scan.labels?.examined, 0);
  assert.deepEqual(scan.labelFindings, []);
  assert.deepEqual(scan.findings.map((f) => f.path), [files.text], "the token inside q3-board.docx is no S2 finding");
  const without = await scanSecretWorkspace([root], { home, fs: recordingFs([]), yieldNow: async () => {} });
  assert.equal(without.labels, null, "no label summary when the source was not asked for");
});

test("the walk, mode count: labelled and unmapped files counted; hostile archives counted; the covered file never opened", async () => {
  const { root, home, files } = tree();
  const opened: string[] = [];
  const scan = await scanSecretWorkspace([root], {
    home, fs: recordingFs(opened), yieldNow: async () => {},
    isCovered: (p) => p === files.covered,
    sensitivityLabels: { mode: "count", isMapped },
  });
  const L = scan.labels!;
  assert.equal(L.mode, "count");
  assert.ok(!opened.includes(files.covered!), "a covered file is never opened");
  assert.equal(L.covered, 1);
  assert.equal(L.examined, 12);
  assert.equal(L.read, 11);
  assert.equal(L.encrypted, 1);
  assert.equal(L.unreadable, 2, "the bomb and the Zip64 archive");
  // hc (HC+GEN), conf, gen, unmapped, unmapped2, otherTenant; draft's label is disabled, plain has none.
  assert.equal(L.files, 6);
  assert.equal(L.mapped, 3, "hc, conf, gen: another tenant's HC is not mapped");
  assert.equal(L.unmappedFiles, 3);
  assert.deepEqual(L.unmapped, [{ id: UNMAPPED, site: TENANT, files: 2 }, { id: HC, site: OTHER_TENANT, files: 1 }]);
  assert.match(scan.capped.lines.join("\n"), /1 encrypted Office file\(s\) not read/);
  assert.match(scan.capped.lines.join("\n"), /2 Office file\(s\) whose sensitivity label could not be read/);
  assert.deepEqual(scan.labelFindings!.map((f) => f.path).sort(), [files.conf, files.gen, files.hc, files.otherTenant, files.unmapped, files.unmapped2].sort());
  const hc = scan.labelFindings!.find((f) => f.path === files.hc)!;
  assert.deepEqual(hc, { path: files.hc, repoRoot: root, labels: [{ id: HC, site: TENANT }, { id: GEN, site: TENANT }] });
  const text = JSON.stringify(scan);
  assert.doesNotMatch(text, new RegExp(`${BODY}|${NAME}|${TOKEN.slice(4, 12)}`), "no file text, no display name");
});

test("the walk, both tiers: the home tier reads an Office file without a name hint; readText false reads no text file", async () => {
  const { home, files } = tree();
  const opened: string[] = [];
  const scan = await scanSecretWorkspace([home], { home, fs: recordingFs(opened), yieldNow: async () => {}, readText: false, sensitivityLabels: { mode: "mapped", isMapped } });
  assert.equal(scan.roots[0]!.tier, "home");
  assert.ok(opened.includes(files.homeDoc!));
  assert.ok(opened.includes(files.hc!), "depth 2 under the home");
  assert.ok(!opened.some((p) => p.startsWith("text:")), "readText: false");
  assert.deepEqual(scan.findings, []);
});

test("the walk: the label budgets (files, bytes) with their lines; the cache hits, and misses on a changed file", async () => {
  const { root, home, files } = tree();
  const few = await scanSecretWorkspace([root], { home, yieldNow: async () => {}, sensitivityLabels: { mode: "count", isMapped, limits: { maxFiles: 2 } } });
  assert.equal(few.labels!.examined, 2);
  assert.equal(few.labels!.capped.overFiles, 10);
  assert.match(few.capped.lines.join("\n"), /10 Office file\(s\) not examined for a sensitivity label: over the 2 file cap/);
  const tight = await scanSecretWorkspace([root], { home, yieldNow: async () => {}, sensitivityLabels: { mode: "count", isMapped, limits: { totalMaxBytes: 6000 } } });
  assert.ok(tight.labels!.bytes <= 6000);
  assert.ok(tight.labels!.capped.overBytes > 0);
  assert.match(tight.capped.lines.join("\n"), /Office file\(s\) not read for a sensitivity label: over the [0-9.]+ MiB total/);

  const cache = new WorkspaceScanCache<LabelCacheEntry>();
  const first = await scanSecretWorkspace([root], { home, yieldNow: async () => {}, sensitivityLabels: { mode: "mapped", isMapped, cache } });
  assert.equal(first.labels!.cached, 0);
  const opened: string[] = [];
  const again = await scanSecretWorkspace([root], { home, fs: recordingFs(opened), yieldNow: async () => {}, sensitivityLabels: { mode: "mapped", isMapped, cache } });
  assert.equal(again.labels!.read, 0);
  assert.equal(again.labels!.cached, first.labels!.read);
  assert.deepEqual(again.labelFindings, first.labelFindings);
  utimesSync(files.gen!, new Date(), new Date(Date.now() + 5000));
  const opened2: string[] = [];
  const third = await scanSecretWorkspace([root], { home, fs: recordingFs(opened2), yieldNow: async () => {}, sensitivityLabels: { mode: "mapped", isMapped, cache } });
  assert.equal(third.labels!.read, 1);
  assert.ok(opened2.includes(files.gen!));
});

// ── the generator ────────────────────────────────────────────────────────────

const LAW = (doc: PolicyFileConfig | null) => {
  const c = compilePolicy({ specId: "claude-code", document: doc });
  return { specId: c.specId, document: doc, pathLabels: c.pathLabels };
};
const F = (path: string, labels: Array<{ id: string; site: string | null }>, repoRoot = "/home/u/proj"): SensitivityLabelFinding => ({ path, repoRoot, labels });

test("the generator: strictest mapped level; public, unmapped and another tenant suggest nothing; the mapping's name; humanOnly below no-model", () => {
  const r = suggestLabelEdits([
    F("/home/u/proj/board/q3-board.docx", [{ id: GEN, site: TENANT }, { id: HC, site: TENANT }]),
    F("/home/u/proj/budget.xlsx", [{ id: CONF, site: null }]),
    F("/home/u/proj/notes.pptx", [{ id: GEN, site: null }]),
    F("/home/u/proj/plan.docm", [{ id: UNMAPPED, site: TENANT }]),
    F("/home/u/proj/partner.docx", [{ id: HC, site: OTHER_TENANT }]),
  ], MAPPING, LAW(null), { home: "/home/u" });
  assert.deepEqual(r.suggestions.map((s) => [s.findingKey, s.edits, s.humanOnly ?? false]), [
    [labelFindingKey("/home/u/proj/board/q3-board.docx"), [{ op: "lock-path", path: "/home/u/proj/board/q3-board.docx", level: "no-model" }], false],
    [labelFindingKey("/home/u/proj/budget.xlsx"), [{ op: "lock-path", path: "/home/u/proj/budget.xlsx", level: "any-model" }], true],
  ].sort((a, b) => String(a[0]).localeCompare(String(b[0]))));
  const hc = r.suggestions.find((s) => s.findingKey.endsWith("q3-board.docx"))!;
  assert.equal(hc.source, "sensitivity-label");
  assert.equal(hc.findingKey, "sensitivity-label:/home/u/proj/board/q3-board.docx");
  assert.equal(hc.sentence, "Make ~/proj/board/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential");
  assert.deepEqual(hc.evidence, { paths: ["board/q3-board.docx"], blobs: [], findings: [], historyOnly: false, label: { id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" } });
  assert.deepEqual(hc.impact, { historicalVersions: 0, workingTreeChanges: true, files: ["board/q3-board.docx"] });
  assert.equal(hc.rotate, false);
  const conf = r.suggestions.find((s) => s.findingKey.endsWith("budget.xlsx"))!;
  assert.equal(conf.sentence, "Make ~/proj/budget.xlsx a secret any AI may read when it asks: its sensitivity label is Confidential");
  assert.deepEqual(r.covered, []);
  assert.deepEqual(r.dropped, []);
});

test("the generator: a law-covered path is covered; a path with its own label is not lowered or replaced below no-model; glob characters escaped", () => {
  const law = LAW({ paths: [{ path: "/home/u/proj/board/**", level: "any-model" }, { path: "/home/u/proj/budget.xlsx", level: "public" }] });
  const r = suggestLabelEdits([
    F("/home/u/proj/board/q3-board.docx", [{ id: HC, site: TENANT }]),
    F("/home/u/proj/budget.xlsx", [{ id: CONF, site: null }]),
    F("/home/u/proj/a[1].docx", [{ id: HC, site: TENANT }]),
  ], MAPPING, law, { home: "/home/u" });
  assert.deepEqual(r.covered.map((c) => c.paths), [["board/q3-board.docx"]]);
  assert.deepEqual(r.dropped.map((d) => [d.findingKey, d.why]), [[labelFindingKey("/home/u/proj/budget.xlsx"), "relaxes"]]);
  assert.deepEqual(r.suggestions.map((s) => s.edits[0]), [{ op: "lock-path", path: "/home/u/proj/a\\[1\\].docx", level: "no-model" }]);
  // A public label of its own is RAISED to no-model (a proven tightening).
  const raise = suggestLabelEdits([F("/home/u/proj/budget.xlsx", [{ id: HC, site: TENANT }])], MAPPING, law, { home: "/home/u" });
  assert.equal(raise.suggestions.length, 1);
});

// ── filing and applying ──────────────────────────────────────────────────────

const REPO = "/home/u/proj";
let dir: string;
let docs: PolicyDocumentStore;
let proposals: PolicyProposalStore;
let protectedPaths: Set<string>;
let ops: PolicySuggestionOps;
let clock = Date.parse("2026-09-30T00:00:00Z");

function rebuild(doc: PolicyFileConfig | null): void {
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: doc }));
}

beforeEach(() => {
  docs?.close();
  proposals?.close();
  dir = mkdtempSync(join(tmpdir(), "mandu-label-ops-"));
  dirs.push(dir);
  const file = join(dir, "policy.yaml");
  writeFileSync(file, yaml.dump({ version: 1, sensitivity_labels: [{ id: HC, name: "Highly Confidential", level: "no-model" }] }));
  const loaded = loadPolicyFileStrict(file);
  rebuild(loaded.config);
  docs = new PolicyDocumentStore({ path: file, rebuild, pollMs: 0, log: () => {} }, { document: loaded.config, found: true });
  proposals = new PolicyProposalStore({ dbPath: join(dir, "mandu.db"), now: () => clock++ });
  protectedPaths = new Set();
  ops = new PolicySuggestionOps({ docs, proposals, exists: () => true, now: () => clock, protectedNow: (p) => protectedPaths.has(p) });
});

function wsWithLabels(labelFindings: SensitivityLabelFinding[]): SecretWorkspaceScan {
  return {
    roots: [{ root: REPO, tier: "workspace" }],
    counts: { examined: 0, read: 0, cached: 0, bytes: 0, covered: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, special: 0, depth: 0, worktrees: 0, lines: [] },
    findings: [], labelFindings, labels: null, limits: DEFAULT_WORKSPACE_LIMITS, ms: 1,
  };
}

function historyScan(rel: string): SecretHistoryScan {
  const d = { kind: "content-shape" as const, rule: "github-token" as const, line: 1, preview: "ghp_…" };
  const f: SecretHistoryFinding = {
    repoRoot: REPO, blob: "a".repeat(40), paths: [rel], firstCommit: "1".repeat(40), lastCommit: "2".repeat(40),
    inHead: true, inIndex: true, stillPresent: true, pathStillSecretByCatalog: false, detector: d, detectors: [d],
  };
  return {
    repos: [{ root: REPO, repoRoot: REPO }], counts: { blobs: 1, scanned: 1, classified: 0 },
    capped: { tooBig: 0, overTotal: 0, overTime: 0, readFailed: 0, binary: 0, pathsUnchecked: 0, untraced: 0, unlisted: false, lines: [] },
    findings: [f], limits: DEFAULT_HISTORY_LIMITS, ms: 1,
  };
}

const mappingNow = (): LabelMappingEntry[] => effectiveLabelMapping(docs.document?.sensitivity_labels ?? []);

test("filing and applying a no-model label: one lock-path, applied on the data plane as a tightening; a rescan files nothing", () => {
  const r = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/q3.docx`, [{ id: HC, site: TENANT }])]) }, { home: "/home/u", labelMapping: mappingNow() });
  assert.equal(r.counts.findings, 1);
  assert.equal(r.counts.filed, 1);
  const v = r.suggestions[0]!;
  assert.equal(v.source, "sensitivity-label");
  assert.equal(v.requestedBy, SCAN_REQUESTER);
  assert.equal(v.humanOnly, false);
  assert.equal(v.evidence.label?.name, "Highly Confidential");
  const a = ops.apply(v.id, { via: "agent-tighten", by: "data-plane" });
  assert.ok(a.applied);
  assert.deepEqual(docs.document?.paths, [{ path: `${REPO}/q3.docx`, level: "no-model" }]);
  const again = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/q3.docx`, [{ id: HC, site: TENANT }])]) }, { labelMapping: mappingNow() });
  assert.equal(again.counts.filed, 0);
  assert.equal(again.counts.covered, 1);
  // No mapping in force: nothing suggested from the same finding.
  assert.equal(ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/other.docx`, [{ id: HC, site: TENANT }])]) }, { labelMapping: [] }).counts.filed, 0);
});

test("a humanOnly label lock: refused on the data plane, applied by a person; closed as covered over a file protected now", () => {
  docs.apply({ ...docs.document!, sensitivity_labels: [{ id: CONF, name: "Confidential", level: "any-model" }] }, { via: "apply", requestedBy: "test", summary: "map" });
  const r = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/budget.xlsx`, [{ id: CONF, site: null }]), F(`${REPO}/keys.xlsx`, [{ id: CONF, site: null }])]) }, { labelMapping: mappingNow() });
  assert.equal(r.counts.filed, 2);
  const [one, two] = [...r.suggestions].sort((a, b) => a.findingKey.localeCompare(b.findingKey));
  assert.ok(one!.humanOnly && two!.humanOnly);
  const refused = ops.apply(one!.id, { via: "agent-tighten", by: "data-plane" });
  assert.ok(!refused.applied && refused.refused === "relaxes");
  assert.match(refused.problems.join(), /only you can approve: apply it in the dashboard/);
  // The admin channel's applySuggestion (`tighten`) is no approval either: only resolvePolicyProposal.
  const adminApply = ops.apply(one!.id, { via: "tighten", by: "human:dashboard" });
  assert.ok(!adminApply.applied && adminApply.refused === "relaxes");
  assert.equal(docs.document?.paths?.some((p) => p.path === `${REPO}/budget.xlsx`) ?? false, false, "nothing applied by either");
  const res = ops.resolve(one!.id, "approved", "human:dashboard");
  assert.ok(res.changeId);
  assert.deepEqual(docs.document?.paths, [{ path: `${REPO}/budget.xlsx`, level: "any-model" }]);
  const change = proposals.getChange(res.changeId!)!;
  assert.equal(change.via, "proposal");
  assert.equal(change.proposalId, one!.id);
  assert.deepEqual(change.delta.map((d) => [d.facet, d.direction]), [["paths", "relax"]], "the one new label, as the delta words it");
  protectedPaths.add(`${REPO}/keys.xlsx`);
  const covered = ops.apply(two!.id, { via: "proposal", by: "human:dashboard" });
  assert.ok(!covered.applied && covered.refused === "covered", "the catalog protects it now: an any-model lock would override that");
  assert.equal(proposals.getProposal(two!.id)!.status, "superseded");
  assert.equal(getCurrentPolicy().pathLabels.size >= 1, true);
});

test("the stricter suggestion wins: a weaker pending label lock is replaced by a history key found later, and by a raised mapping; a dismissal blocks", () => {
  docs.apply({ ...docs.document!, sensitivity_labels: [{ id: CONF, name: "Confidential", level: "any-model" }] }, { via: "apply", requestedBy: "test", summary: "map" });
  const first = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/a.docx`, [{ id: CONF, site: null }]), F(`${REPO}/b.docx`, [{ id: CONF, site: null }]), F(`${REPO}/c.docx`, [{ id: CONF, site: null }])]) }, { labelMapping: mappingNow() });
  assert.equal(first.counts.filed, 3);
  const id = (p: string): string => first.suggestions.find((s) => s.edits[0]!.op === "lock-path" && (s.edits[0] as { path: string }).path === `${REPO}/${p}`)!.id;

  // A history key in a.docx: no-model beats the pending any-model label lock.
  const h = ops.fileFromScans({ history: historyScan("a.docx") }, { labelMapping: mappingNow() });
  assert.equal(h.counts.filed, 1);
  assert.equal(h.counts.superseded, 1);
  const old = proposals.getProposal(id("a.docx"))!;
  assert.equal(old.status, "superseded");
  assert.equal(old.supersededBy, h.filed[0]);

  // The mapping is raised: b.docx's new suggestion (same finding key) replaces the old.
  docs.apply({ ...docs.document!, sensitivity_labels: [{ id: CONF, name: "Confidential", level: "no-model" }] }, { via: "apply", requestedBy: "test", summary: "raise" });
  ops.dismiss(id("c.docx"), "human:dashboard");
  const raised = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/b.docx`, [{ id: CONF, site: null }]), F(`${REPO}/c.docx`, [{ id: CONF, site: null }])]) }, { labelMapping: mappingNow() });
  assert.equal(raised.counts.filed, 1, "b.docx again, at no-model");
  assert.equal(raised.counts.dismissed, 1, "c.docx was dismissed: Not a secret is about the file");
  assert.equal(proposals.getProposal(id("b.docx"))!.status, "superseded");
  const b = raised.suggestions.find((s) => s.findingKey === labelFindingKey(`${REPO}/b.docx`))!;
  assert.deepEqual(b.edits, [{ op: "lock-path", path: `${REPO}/b.docx`, level: "no-model" }]);
  assert.equal(b.humanOnly, false);

  // The same level again files nothing (already pending), and a weaker one never replaces a stricter one.
  const same = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/b.docx`, [{ id: CONF, site: null }])]) }, { labelMapping: mappingNow() });
  assert.equal(same.counts.filed, 0);
  assert.equal(same.counts.alreadyPending, 1);
  const weaker = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/a.docx`, [{ id: CONF, site: null }])]) }, { labelMapping: effectiveLabelMapping([{ id: CONF, name: "C", level: "any-model" }]) });
  assert.equal(weaker.counts.filed, 0);
});

test("§14.12: a model's stricter single-file answer replaces a weaker pending suggestion for the same file, as the scans' does; a weaker or equal one does not; a dismissal blocks", () => {
  const contents = (path: string, level: "no-model" | "local-model" | "any-model"): Suggestion => ({
    findingKey: contentsFindingKey(path), source: "model-contents", repoRoot: REPO,
    edits: [{ op: "lock-path", path, level }],
    sentence: `Make ${path} hidden from the AI`,
    evidence: { paths: [path.slice(REPO.length + 1)], blobs: [], findings: [], historyOnly: false },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: [path.slice(REPO.length + 1)] },
    historyOnly: false, rotate: false,
    model: { endpoint: "own", level, reason: "legal", reasonWords: "looks like legal documents", candidate: "file", files: 1, covers: [] },
    ...(level === "no-model" ? {} : { humanOnly: true }),
  });
  // A label mapped to any-model is pending on r.docx; the model then calls the file no-model.
  docs.apply({ ...docs.document!, sensitivity_labels: [{ id: CONF, name: "Confidential", level: "any-model" }] }, { via: "apply", requestedBy: "test", summary: "map" });
  const lab = ops.fileFromScans({ workspace: wsWithLabels([F(`${REPO}/r.docx`, [{ id: CONF, site: null }])]) }, { labelMapping: mappingNow() });
  assert.equal(lab.counts.filed, 1);
  const m = ops.fileModelSuggestions([contents(`${REPO}/r.docx`, "no-model")]);
  assert.equal(m.counts.filed, 1);
  assert.equal(m.counts.superseded, 1);
  const old = proposals.getProposal(lab.filed[0]!)!;
  assert.equal(old.status, "superseded");
  assert.equal(old.supersededBy, m.filed[0]);

  // A model run answers local-model for notes.md (a person must apply it);
  // a later run says no-model: it replaces it (the same finding key).
  const first = ops.fileModelSuggestions([contents(`${REPO}/notes.md`, "local-model")]);
  assert.equal(first.counts.filed, 1);
  const again = ops.fileModelSuggestions([contents(`${REPO}/notes.md`, "no-model")]);
  assert.equal(again.counts.filed, 1);
  assert.equal(again.counts.superseded, 1);
  assert.equal(proposals.getProposal(first.filed[0]!)!.supersededBy, again.filed[0]);

  // Equal or weaker: already pending, nothing replaced.
  assert.deepEqual(ops.fileModelSuggestions([contents(`${REPO}/notes.md`, "no-model")]).counts, { filed: 0, alreadyPending: 1, dismissed: 0, overCap: 0, superseded: 0 });
  assert.equal(ops.fileModelSuggestions([contents(`${REPO}/notes.md`, "any-model")]).counts.alreadyPending, 1);
  assert.equal(proposals.getProposal(again.filed[0]!)!.status, "pending");

  // Not a secret is about the file: a stricter model answer does not bring it back.
  ops.dismiss(again.filed[0]!, "human:dashboard");
  const after = ops.fileModelSuggestions([contents(`${REPO}/notes.md`, "no-model")]);
  assert.equal(after.counts.filed, 0);
  assert.equal(after.counts.dismissed, 1);
});
