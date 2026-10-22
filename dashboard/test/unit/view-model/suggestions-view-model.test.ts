/**
 * suggestions-view-model.test — the explorer's Suggested view as rows
 * (dashboard.md §4.25r, confidentiality-plan-14 §5.4; view-model/suggestions.ts).
 *
 * Pins: a path only git history holds is its own row, tagged; a key once
 * inline in a file that is harmless now is a sub-row of old versions under
 * that file; a suggestion this Mandu cannot apply says why; the detector,
 * mask, commit range, impact, rotation advice and policy.yaml lines in words;
 * a file the workspace scan found (plan 14 §13) is an ordinary row with no
 * tag and no commits, its detector with its line, the softer advice and
 * "from the next time an agent starts"; on macOS a history row's impact
 * says it hides the committed versions on Linux and that they stay readable
 * there (the Linux words unchanged); the scan's one-line summary names
 * both scans, the home folder, and what a cap left unchecked in plain words;
 * and every string passes the product vocabulary sweep (§4.16 / the home
 * page's FORBIDDEN list). The fixtures carry masks only, as the arbiter's
 * scan does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BLOCKED_WORDS,
  HISTORY_TAG,
  MACOS_HISTORY_WORDS,
  ROTATE_SOFT_WORDS,
  ROTATE_WORDS,
  MACOS_ROTATE_WORDS,
  SUGGESTED_BY,
  WORKSPACE_IMPACT,
  WORKSPACE_NOTE,
  scanSummary,
  suggestionRows,
  whenWords,
  workspaceCappedWords,
  yamlLines,
  type SuggestionWire,
  type SuggestPolicyWire,
  type WorkspaceScanWire,
} from "../../../src/view-model/suggestions.js";

const HOME = "/home/u";
const REPO = "/home/u/proj";

function suggestion(over: Partial<SuggestionWire>): SuggestionWire {
  return {
    id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan",
    findingKey: "git-history:path:/home/u/proj/deploy/id_rsa", source: "git-history", repoRoot: REPO,
    edits: [{ op: "lock-path", path: `${REPO}/deploy/id_rsa`, level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_rsa a secret no AI may read (only in git history)",
    evidence: {
      paths: ["deploy/id_rsa"], blobs: ["a".repeat(40)], historyOnly: true,
      findings: [{
        blob: "a".repeat(40), paths: ["deploy/id_rsa"], firstCommit: "1111111aaaa", lastCommit: "2222222bbbb",
        inHead: false, inIndex: false, stillPresent: false,
        detectors: [
          { kind: "content-shape", rule: "private-key", mask: "(key block header)…", words: "private key", line: 1 },
          { kind: "catalog-path", rule: "catalog:ssh-private-key", mask: "deploy/id_rsa", words: "a file named like a credential file", path: "deploy/id_rsa" },
        ],
      }],
    },
    impact: { historicalVersions: 2, workingTreeChanges: false, files: [] },
    historyOnly: true, rotate: true, applicable: true,
    createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
    ...over,
  };
}

const BLOB = "c".repeat(40);
const blobSuggestion = suggestion({
  id: "pp-000002",
  findingKey: `git-history:blob:sha1:${BLOB}`,
  edits: [{ op: "lock-blob", blob: `sha1:${BLOB}`, level: "no-model", note: "found in history: config.py (3333333..4444444)" }],
  sentence: "Hide an old version of ~/proj/config.py from the AI",
  evidence: {
    paths: ["config.py"], blobs: [BLOB], historyOnly: false,
    findings: [{
      blob: BLOB, paths: ["config.py"], firstCommit: "3333333cccc", lastCommit: "4444444dddd",
      inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 1 }],
    }],
  },
  impact: { historicalVersions: 1, workingTreeChanges: false, files: [] },
  historyOnly: false, applicable: false,
});

test("a path only git history holds is its own row, tagged, with the evidence in words", () => {
  const [row] = suggestionRows([suggestion({})], HOME, "linux");
  assert.equal(row!.kind, "path");
  assert.equal(row!.path, `${REPO}/deploy/id_rsa`);
  assert.equal(row!.display, "~/proj/deploy/id_rsa");
  assert.equal(row!.name, "id_rsa");
  assert.equal(row!.parent, null);
  assert.equal(row!.historyOnly, true);
  assert.equal(row!.tag, HISTORY_TAG);
  assert.equal(row!.repo, "~/proj");
  assert.deepEqual(row!.found, [
    { words: "Looks like a private key", mask: "(key block header)…" },
    { words: "A file named like a credential file", mask: "deploy/id_rsa" },
  ]);
  assert.deepEqual(row!.when, ["Added in 1111111, removed in 2222222"]);
  assert.equal(row!.impact, "Hides 2 old versions in git history from the AI. No file you have now changes.");
  assert.equal(row!.rotate, ROTATE_WORDS);
  assert.equal(row!.by, SUGGESTED_BY);
  assert.equal(row!.applicable, true);
  assert.equal(row!.blocked, null);
  assert.equal(row!.yaml, `paths:\n  - path: ${REPO}/deploy/id_rsa\n    level: no-model`);
  assert.deepEqual(row!.more, []);
});

test("old versions of a file that is harmless now are a sub-row under it; one this Mandu cannot apply says why", () => {
  const [row] = suggestionRows([blobSuggestion], HOME, "linux");
  assert.equal(row!.kind, "versions");
  assert.equal(row!.name, "1 old version of config.py");
  assert.deepEqual(row!.parent, { path: `${REPO}/config.py`, display: "~/proj/config.py", name: "config.py" });
  assert.equal(row!.tag, null, "the file is still there");
  assert.equal(row!.impact, "Hides 1 old version in git history from the AI. The file as it is now does not change.");
  assert.equal(row!.applicable, false);
  assert.equal(row!.blocked, BLOCKED_WORDS);
  assert.deepEqual(row!.found, [{ words: "Looks like a GitHub token", mask: "ghp_…" }]);
  assert.equal(row!.yaml, `blobs:\n  - id: sha1:${BLOB}\n    level: no-model\n    note: "found in history: config.py (3333333..4444444)"`);
});

test("a file that still holds the key: no tag, and Save hides the file as it is now too; a renamed key lists its other paths", () => {
  const s = suggestion({
    id: "pp-000003", historyOnly: false,
    edits: [
      { op: "lock-path", path: `${REPO}/.env.prod`, level: "no-model" },
      { op: "lock-path", path: `${REPO}/old/.env.prod`, level: "no-model" },
    ],
    evidence: { ...suggestion({}).evidence, paths: [".env.prod", "old/.env.prod"], historyOnly: false },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: [".env.prod"] },
  });
  const [row] = suggestionRows([s], HOME, "linux");
  assert.equal(row!.tag, null);
  assert.equal(row!.impact, "Hides it in git history from the AI, and the file as it is now too.");
  assert.deepEqual(row!.more, ["~/proj/old/.env.prod"]);
  assert.equal(row!.yaml.split("\n").filter((l) => l.startsWith("  - path:")).length, 2);
});

/** A key in a file that still exists (the history part and the file). */
const presentSuggestion = suggestion({
  id: "pp-000005", historyOnly: false,
  edits: [{ op: "lock-path", path: `${REPO}/.env.prod`, level: "no-model" }],
  evidence: { ...suggestion({}).evidence, paths: [".env.prod"], historyOnly: false },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: [".env.prod"] },
});

test("macOS: a history row says it hides the committed versions on Linux and that they stay readable here; a workspace row is unchanged; Linux keeps its words", () => {
  const views = [suggestion({}), blobSuggestion, presentSuggestion, wsSuggestion];
  const [gone, versions, present, workspace] = suggestionRows(views, HOME, "darwin");
  assert.equal(gone!.impact, `Hides 2 old versions in git history from the AI on Linux. ${MACOS_HISTORY_WORDS} No file you have now changes.`);
  assert.equal(versions!.impact, `Hides 1 old version in git history from the AI on Linux. ${MACOS_HISTORY_WORDS} The file as it is now does not change.`);
  assert.equal(present!.impact,
    "Hides it in git history from the AI on Linux, and the file as it is now too. On macOS the AI cannot read the file as it is now, but the committed versions stay readable.");
  for (const r of [gone, versions, present]) assert.match(r!.impact, /from the AI on Linux\b.* On macOS .*committed versions stay readable/, r!.impact);
  assert.equal(workspace!.impact, WORKSPACE_IMPACT, "a workspace row promises only the file, which macOS does make unreadable");
  // The rotate advice does not claim a rule keeps the history from the AI.
  assert.equal(gone!.rotate, MACOS_ROTATE_WORDS);
  assert.match(MACOS_ROTATE_WORDS, /on macOS a rule does not keep the AI from reading its committed versions/);
  assert.equal(suggestionRows(views, HOME, "linux")[0]!.rotate, ROTATE_WORDS);
  // Linux: the same rows keep their words and never name macOS.
  const linux = suggestionRows(views, HOME, "linux");
  assert.deepEqual(linux.map((r) => r.impact), [
    "Hides 2 old versions in git history from the AI. No file you have now changes.",
    "Hides 1 old version in git history from the AI. The file as it is now does not change.",
    "Hides it in git history from the AI, and the file as it is now too.",
    WORKSPACE_IMPACT,
  ]);
  // Without a platform, the rows are worded for this host.
  assert.deepEqual(suggestionRows(views, HOME).map((r) => r.impact), suggestionRows(views, HOME, process.platform).map((r) => r.impact));
});

/** A workspace suggestion as the arbiter files it (plan 14 §13.4, §13.8). */
const wsSuggestion = suggestion({
  id: "pp-000004", source: "workspace", findingKey: `workspace:path:${REPO}/deploy/staging.conf`,
  edits: [{ op: "lock-path", path: `${REPO}/deploy/staging.conf`, level: "no-model" }],
  sentence: "Make ~/proj/deploy/staging.conf a secret no AI may read",
  evidence: {
    paths: ["deploy/staging.conf"], blobs: [], historyOnly: false,
    findings: [{
      blob: "", paths: ["deploy/staging.conf"], firstCommit: null, lastCommit: null, inHead: false, inIndex: false, stillPresent: true,
      detectors: [
        { kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 },
        { kind: "content-shape", rule: "aws-access-key", mask: "AKIA…", words: "AWS access key", line: 5 },
      ],
    }],
  },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/staging.conf"] },
  historyOnly: false, rotate: false,
});

test("a file the workspace scan found: an ordinary row, no tag and no commits, the detector with its line, the softer advice", () => {
  const [row] = suggestionRows([wsSuggestion], HOME);
  assert.equal(row!.source, "workspace");
  assert.equal(row!.kind, "path");
  assert.equal(row!.path, `${REPO}/deploy/staging.conf`);
  assert.equal(row!.display, "~/proj/deploy/staging.conf");
  assert.equal(row!.name, "staging.conf");
  assert.equal(row!.parent, null);
  assert.equal(row!.historyOnly, false, "not greyed");
  assert.equal(row!.tag, null, "no 'only in git history' tag");
  assert.deepEqual(row!.when, [], "no commit lines");
  assert.deepEqual(row!.found, [
    { words: "Looks like a GitHub token", mask: "ghp_…", line: 2 },
    { words: "Looks like an AWS access key", mask: "AKIA…", line: 5 },
  ]);
  assert.equal(row!.note, WORKSPACE_NOTE);
  assert.equal(row!.impact, WORKSPACE_IMPACT);
  assert.match(row!.impact, /from the next time an agent starts/);
  assert.equal(row!.rotate, ROTATE_SOFT_WORDS);
  assert.match(row!.rotate!, /^If an AI session read this file before, rotate the key/);
  assert.equal(row!.rotateSoft, true);
  assert.equal(row!.by, SUGGESTED_BY);
  assert.equal(row!.applicable, true);
  assert.deepEqual(row!.more, [], "the repo-relative evidence path is the row's own path");
  assert.equal(row!.yaml, `paths:\n  - path: ${REPO}/deploy/staging.conf\n    level: no-model`);
  // A history row keeps its own advice, commits and no line.
  const [hist] = suggestionRows([suggestion({})], HOME);
  assert.equal(hist!.source, "git-history");
  assert.equal(hist!.rotateSoft, false);
  assert.equal(hist!.note, null);
  assert.equal("line" in hist!.found[0]!, false);
});

test("when words: traced, still there, and not traced", () => {
  assert.equal(whenWords({ firstCommit: "abcdef0123", lastCommit: "abcdef0123", inHead: true, inIndex: false }), "Added in abcdef0, still in the current version");
  assert.equal(whenWords({ firstCommit: "abcdef0123", lastCommit: "abcdef0123", inHead: false, inIndex: false }), "In abcdef0");
  assert.equal(whenWords({ firstCommit: "abcdef0123", lastCommit: "9876543210", inHead: true, inIndex: false }), "Added in abcdef0, last changed in 9876543");
  assert.equal(whenWords({ firstCommit: null, lastCommit: null, inHead: false, inIndex: true }), "In the current version (commits not traced)");
  assert.equal(whenWords({ firstCommit: null, lastCommit: null, inHead: false, inIndex: false }), "Commits not traced");
});

test("yaml lines quote a path that needs it", () => {
  assert.equal(yamlLines([{ op: "lock-path", path: "/home/u/my proj/key: x", level: "no-model" }]), 'paths:\n  - path: "/home/u/my proj/key: x"\n    level: no-model');
});

function scan(over: Partial<SuggestPolicyWire> = {}): SuggestPolicyWire {
  return {
    axis: true, running: false, suggestions: [suggestion({})], filed: ["pp-000001"], covered: [],
    counts: { findings: 2, suggested: 2, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 },
    scan: { repos: [{ root: REPO, repoRoot: REPO }], capped: { tooBig: 0, overTotal: 0, overTime: 0, untraced: 0, unlisted: false }, ms: 10 },
    ...over,
  };
}

const NO_CAPS: WorkspaceScanWire["capped"] = { tooBig: 0, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, special: 0, depth: 0, lines: [] };
function ws(over: Partial<WorkspaceScanWire> = {}): WorkspaceScanWire {
  return {
    roots: [{ root: REPO, tier: "workspace" }],
    counts: { examined: 1300, read: 1004, cached: 200, bytes: 1 << 20, covered: 0 },
    capped: NO_CAPS,
    limits: { fileMaxBytes: 256 * 1024, totalMaxBytes: 64 * 1024 * 1024, maxFiles: 20_000, timeoutMs: 30_000 },
    ms: 40,
    ...over,
  };
}

test("the scan in one line (git history): found, covered, dismissed, over the cap, capped, no repository, the switch off", () => {
  assert.equal(scanSummary(scan(), HOME), "Scanned the git history of ~/proj. 1 possible key to review.");
  assert.equal(scanSummary(scan({ suggestions: [suggestion({}), blobSuggestion] }), HOME), "Scanned the git history of ~/proj. 2 possible keys to review (1 new).");
  assert.equal(scanSummary(scan({ suggestions: [], counts: { ...scan().counts, filed: 0, covered: 2, dismissed: 1, overCap: 3 } }), HOME),
    "Scanned the git history of ~/proj. Nothing new to review. 2 keys are already protected. 1 finding you marked as not a secret was left out. 3 more wait until you review these.");
  assert.match(scanSummary(scan({ scan: { ...scan().scan!, capped: { tooBig: 1, overTotal: 0, overTime: 0, untraced: 0, unlisted: false } } }), HOME), /too large to read in time/);
  // git failing to hand blobs over is not the time budget, and is said.
  const failedRead = scanSummary(scan({ scan: { ...scan().scan!, capped: { tooBig: 0, overTotal: 0, overTime: 0, readFailed: 2, untraced: 0, unlisted: false } } }), HOME);
  assert.match(failedRead, /Part of the history could not be read, so there may be more\.$/);
  assert.doesNotMatch(failedRead, /in time/);
  assert.equal(scanSummary(scan({ scan: { ...scan().scan!, repos: [{ root: "/home/u/notes", repoRoot: null, reason: "not a git repository" }] } }), HOME), "No git history was found in ~/notes.");
  assert.equal(scanSummary(scan({ scan: { ...scan().scan!, repos: [{ root: REPO, repoRoot: REPO }, { root: "/w/b", repoRoot: "/w/b" }] } }), HOME), "Scanned the git history of 2 projects. 1 possible key to review.");
  assert.match(scanSummary(scan({ axis: false }), HOME), /^Protection is off, so nothing was scanned\. Turn it on in Settings to scan\.$/);
});

test("the scan in one line names both scans: the git history and the files read, the home folder, a folder with no history", () => {
  assert.equal(scanSummary(scan({ workspaceScan: ws() }), HOME), "Scanned the git history of ~/proj and 1,204 files. 1 possible key to review.");
  assert.equal(
    scanSummary(scan({ workspaceScan: ws({ roots: [{ root: REPO, tier: "workspace" }, { root: HOME, tier: "home" }], counts: { ...ws().counts, covered: 2 } }) }), HOME),
    "Scanned the git history of ~/proj and 1,204 files in ~/proj and your home folder. 1 possible key to review. 2 files your rules already protect were not opened.",
  );
  // The workspace scan alone (the history was not asked for).
  assert.equal(scanSummary(scan({ scan: null, suggestions: [wsSuggestion], workspaceScan: ws({ counts: { ...ws().counts, read: 1, cached: 0 } }) }), HOME), "Scanned 1 file in ~/proj. 1 possible key to review.");
  // A folder with no git history still has its files read.
  assert.equal(
    scanSummary(scan({ suggestions: [], counts: { ...scan().counts, filed: 0 }, scan: { ...scan().scan!, repos: [{ root: "/home/u/notes", repoRoot: null, reason: "not a git repository" }] }, workspaceScan: ws({ roots: [{ root: "/home/u/notes", tier: "workspace" }] }) }), HOME),
    "Scanned 1,204 files in ~/notes. Nothing new to review. No git history was found in ~/notes.",
  );
  // A folder that could not be scanned is named; one inside another is not (it was read as part of it).
  assert.equal(
    scanSummary(scan({ workspaceScan: ws({ roots: [{ root: REPO, tier: "workspace" }, { root: `${REPO}/sub`, tier: "workspace", reason: "inside another root" }, { root: "/home/u/gone", tier: "workspace", reason: "does not exist or cannot be read" }] }) }), HOME),
    "Scanned the git history of ~/proj and 1,204 files. 1 possible key to review. Not scanned: ~/gone (does not exist or cannot be read).",
  );
});

test("what a cap left unchecked, in plain words, and whether there may be more", () => {
  assert.equal(workspaceCappedWords(ws()), null);
  assert.equal(
    workspaceCappedWords(ws({ capped: { ...NO_CAPS, tooBig: 2, overTime: 40, binary: 3, symlinks: 1, depth: 1 } })),
    "Not checked: 2 files over 256 KB, 40 files or folders left when its 30 seconds ran out, 1 folder nested too deep, 3 binary files and 1 link to a file. There may be more keys in those.",
  );
  assert.equal(workspaceCappedWords(ws({ capped: { ...NO_CAPS, binary: 1, special: 1 } })), "Not checked: 1 binary file and 1 special file.");
  // Linked work trees are second checkouts (plan 14 §13.9): named, not a gap.
  assert.equal(workspaceCappedWords(ws({ capped: { ...NO_CAPS, worktrees: 39 } })), "Not checked: 39 extra copies of a git project.");
  assert.equal(
    workspaceCappedWords(ws({ capped: { ...NO_CAPS, overTotal: 5, overFiles: 7, unreadable: 1 } })),
    "Not checked: 5 files past the 64 MB it reads in all, 7 files past the 20,000 it looks at and 1 file or folder it could not open. There may be more keys in those.",
  );
  assert.match(scanSummary(scan({ workspaceScan: ws({ capped: { ...NO_CAPS, tooBig: 1 } }) }), HOME), / Not checked: 1 file over 256 KB\. There may be more keys in those\.$/);
});

/** The home page's sweep (home-view-model.test.ts): no inspector term in product copy. */
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;

test("every string of a row and of a summary uses the product vocabulary only", () => {
  const views = [suggestion({}), blobSuggestion, presentSuggestion, wsSuggestion];
  const rows = [...suggestionRows(views, HOME, "linux"), ...suggestionRows(views, HOME, "darwin")];
  const allCaps = { tooBig: 1, overTotal: 1, overTime: 1, overFiles: 1, binary: 1, symlinks: 1, unreadable: 1, special: 1, depth: 1, lines: [] };
  const oddRoots: WorkspaceScanWire["roots"] = [
    { root: "/home/u/.mandu", tier: "workspace", reason: "Mandu's own state, not scanned" },
    { root: "/home/u/.claude", tier: "workspace", reason: "the agent's own credentials, not scanned" },
    { root: "/proc/1", tier: "workspace", reason: "a kernel pseudo-filesystem, not scanned" },
    { root: "/home/u/f", tier: "workspace", reason: "not a directory" },
  ];
  const copy = [
    ...rows.flatMap((r) => [r.name, r.tag ?? "", r.sentence, r.impact, r.rotate ?? "", r.note ?? "", r.by, r.blocked ?? "", ...r.when, ...r.found.map((f) => f.words)]),
    scanSummary(scan(), HOME), scanSummary(scan({ axis: false }), HOME),
    scanSummary(scan({ suggestions: [], counts: { ...scan().counts, covered: 1, dismissed: 2, overCap: 1 } }), HOME),
    scanSummary(scan({ workspaceScan: ws({ roots: [...ws().roots, { root: HOME, tier: "home" }, ...oddRoots], capped: allCaps, counts: { ...ws().counts, covered: 3 } }) }), HOME),
    BLOCKED_WORDS, ROTATE_WORDS, MACOS_ROTATE_WORDS, ROTATE_SOFT_WORDS, WORKSPACE_IMPACT, WORKSPACE_NOTE, SUGGESTED_BY, HISTORY_TAG, MACOS_HISTORY_WORDS,
  ].join("\n");
  // The arbiter's own capped lines name settings; the page words them itself.
  assert.doesNotMatch(copy, /MANDU_|root\(s\)|entr\(ies\)/, copy);
  assert.doesNotMatch(copy, FORBIDDEN, copy);
});

test("a names-only model's rule (plan 14 §14.10): a row on its folder, suggested by the model, the reason in words, what Save hides; no commits, no mask, no rotation", () => {
  const [row] = suggestionRows([suggestion({
    id: "pp-000009", source: "model-names", findingKey: `model-names:path:${REPO}/clients`,
    edits: [{ op: "lock-path", path: `${REPO}/clients`, level: "no-model" }],
    sentence: "Make ~/proj/clients a secret no AI may read: covers 1 suggestion below",
    evidence: { paths: ["clients"], blobs: [], findings: [], historyOnly: false },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: ["clients"] },
    historyOnly: false, rotate: false,
    model: { endpoint: "Claude (claude -p)", level: "local-model", reason: "customer-data", reasonWords: "looks like customer data", candidate: "folder", files: 4, covers: ["pp-000003"] },
  })], HOME);
  assert.ok(row);
  assert.equal(row.source, "model-names");
  assert.equal(row.kind, "path");
  assert.equal(row.path, `${REPO}/clients`);
  assert.equal(row.name, "clients");
  assert.equal(row.level, "no-model");
  assert.equal(row.by, "Suggested by your model Claude (claude -p)");
  assert.deepEqual(row.found, [{ words: "Looks like customer data", mask: "from the folder's file names" }]);
  assert.equal(row.impact, "Hides this folder and everything in it (4 files the scan listed) from the AI from the next time an agent starts. Saving it also closes the 1 suggestion it covers.");
  assert.equal(row.note, "Your model saw only file and folder names, never what the files hold.");
  assert.deepEqual([row.rotate, row.tag, row.when, row.historyOnly], [null, null, [], false]);
  assert.doesNotMatch([row.by, row.impact, row.note, ...row.found.map((f) => f.words + f.mask)].join(" "), FORBIDDEN);
  const [file] = suggestionRows([suggestion({
    source: "model-names", edits: [{ op: "lock-path", path: `${REPO}/notes/diary.md`, level: "no-model" }],
    evidence: { paths: ["notes/diary.md"], blobs: [], findings: [], historyOnly: false }, historyOnly: false, rotate: false,
    model: { endpoint: "m", level: "no-model", reason: "personal", reasonWords: "looks like personal documents", candidate: "file", files: 1, covers: [] },
  })], HOME);
  assert.equal(file!.impact, WORKSPACE_IMPACT);
  assert.equal(file!.found[0]!.mask, "from the file's name");
});

test("a file whose key mandu scan found in past sessions (plan 17 §3 item 13): a file row, the key names, the full advice, by mandu scan", () => {
  const past = suggestion({
    id: "pp-000009", source: "past-sessions", findingKey: `past-sessions:path:${HOME}/.config/cli/config.yml`, repoRoot: `${HOME}/.config/cli`,
    edits: [{ op: "lock-path", path: `${HOME}/.config/cli/config.yml`, level: "no-model" }],
    sentence: "Make ~/.config/cli/config.yml a secret no AI may read",
    evidence: { paths: ["config.yml"], blobs: [], historyOnly: false, findings: [], pastSessions: { names: ["token"], sessions: 3, last: "2026-10-19T08:00:00.000Z" } },
    impact: { historicalVersions: 0, workingTreeChanges: true, files: ["config.yml"] },
    historyOnly: false, rotate: true,
  });
  const [row] = suggestionRows([past], HOME);
  assert.equal(row!.source, "past-sessions");
  assert.equal(row!.kind, "path");
  assert.equal(row!.display, "~/.config/cli/config.yml");
  assert.equal(row!.tag, null);
  assert.deepEqual(row!.when, []);
  assert.deepEqual(row!.found, [{ words: "Reached the AI in a past session", mask: "token" }]);
  assert.equal(row!.note, "mandu scan found a key from this file in what your agents sent to the AI in 3 past sessions. Nothing protects the file yet.");
  assert.equal(row!.impact, WORKSPACE_IMPACT);
  assert.equal(row!.rotate, ROTATE_WORDS, "the key did leave: the full advice");
  assert.equal(row!.rotateSoft, false);
  assert.equal(row!.by, "Suggested by mandu scan");
});
