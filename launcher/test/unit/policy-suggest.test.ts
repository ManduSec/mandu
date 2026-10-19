/**
 * policy-suggest.test — `mandu policy suggest` and the launch-time notice
 * (confidentiality-plan-14-policy-suggestions.md §5.3, §5.5) over mocked
 * seams: flag parsing, the TTY / no-TTY rules, the rendering of a
 * SuggestionView (the mask is what is shown, never more), the review's key
 * handling with scripted keys, --apply-all's typed confirmation, the
 * throwaway arbiter's refusal to apply, and the launch notice's decision and
 * budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyOutcome, clean, hidesHistory, impactLine, jsonText, launchSuggestConfig, launchSuggestionNotice, parsePolicySuggestArgs, policyYamlLines, realPolicySuggestDeps,
  readReviewKey, renderScanHeader, renderSuggestion, runPolicy, runPolicySuggest, startLaunchSuggest, suggestCallBudgetMs, suggestMode,
  fromEarlierScan, EARLIER_SCAN_NOTE, suggestionsFor, whyNotApplicable, workspaceScanPhrase, yamlScalar, DISMISS_NOTE, HUMAN_ONLY_LINE, LABEL_LOWER_LINE, LABEL_SOURCE_LINE, LAUNCH_SUGGEST_MARGIN_MS, MACOS_APPLIED_NOTE, MACOS_HISTORY_LINE, MACOS_ROTATE_LINE, ROTATE_LINE, WORKSPACE_IMPACT_LINE, WORKSPACE_ROTATE_LINE,
  type ApplySuggestionWire, type PolicySuggestDeps, type SuggestOptsWire, type SuggestPolicyWire, type SuggestionViewWire, type WorkspaceScanWire,
} from "../../src/policy-suggest.js";
import { Layout } from "../../src/services/layout.js";
import { compactNotice } from "../../src/launch-banner.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the suggestions exist only with the confidentiality axis on

const HOME = "/home/u";
const REPO = `${HOME}/proj`;
// A mask as the scan builds it (assembled: this file holds no PEM header line).
const PEM_MASK = "-----BEGIN OPENSSH " + "PRIVATE KEY-----…";
const layout = {} as Layout;

function view(over: Partial<SuggestionViewWire> = {}): SuggestionViewWire {
  return {
    id: "pp-000001", kind: "suggestion", status: "pending", requestedBy: "mandu:scan",
    findingKey: `git-history:path:${REPO}/deploy/id_ed25519`, source: "git-history", repoRoot: REPO,
    edits: [{ op: "lock-path", path: `${REPO}/deploy/id_ed25519`, level: "no-model" }],
    sentence: "Make ~/proj/deploy/id_ed25519 a secret no AI may read (only in git history)",
    evidence: {
      paths: ["deploy/id_ed25519"], blobs: ["a".repeat(40)], historyOnly: true,
      findings: [{
        blob: "a".repeat(40), paths: ["deploy/id_ed25519"], firstCommit: "1111111122222222", lastCommit: "3333333344444444",
        inHead: false, inIndex: false, stillPresent: false,
        detectors: [{ kind: "content-shape", rule: "private-key", mask: PEM_MASK, words: "private key", line: 1 }],
      }],
    },
    impact: { historicalVersions: 1, workingTreeChanges: false, files: [] },
    historyOnly: true, rotate: true, applicable: true,
    createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
    ...over,
  };
}

const blobView = (): SuggestionViewWire => view({
  id: "pp-000002", findingKey: `git-history:blob:sha1:${"b".repeat(40)}`,
  edits: [{ op: "lock-blob", blob: `sha1:${"b".repeat(40)}`, level: "no-model", note: "found in history: config.py (11111111..33333333)" }],
  sentence: "Hide an old version of ~/proj/config.py from the AI", historyOnly: false, applicable: false,
  evidence: {
    paths: ["config.py"], blobs: ["b".repeat(40)], historyOnly: false,
    findings: [{
      blob: "b".repeat(40), paths: ["config.py"], firstCommit: "1111111122222222", lastCommit: "3333333344444444",
      inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }],
    }],
  },
});

/** A workspace suggestion (plan 14 §13.4) as the arbiter builds it. */
const wsView = (over: Partial<SuggestionViewWire> = {}): SuggestionViewWire => view({
  id: "pp-000003", source: "workspace", findingKey: `workspace:path:${REPO}/deploy/staging.conf`,
  edits: [{ op: "lock-path", path: `${REPO}/deploy/staging.conf`, level: "no-model" }],
  sentence: "Make ~/proj/deploy/staging.conf a secret no AI may read",
  evidence: {
    paths: ["deploy/staging.conf"], blobs: [], historyOnly: false,
    findings: [{
      blob: "", paths: ["deploy/staging.conf"], firstCommit: null, lastCommit: null,
      inHead: false, inIndex: false, stillPresent: true,
      detectors: [{ kind: "content-shape", rule: "github-token", mask: "ghp_…", words: "GitHub token", line: 2 }],
    }],
  },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/staging.conf"] },
  historyOnly: false, rotate: false, applicable: true, createdAt: 2,
  ...over,
});

const wsScan = (over: Partial<WorkspaceScanWire> = {}): WorkspaceScanWire => ({
  roots: [{ root: REPO, tier: "workspace" }],
  counts: { examined: 1204, read: 38, cached: 1160, bytes: 90_000, covered: 6 },
  capped: { tooBig: 2, overTotal: 0, overTime: 0, overFiles: 0, binary: 0, symlinks: 0, unreadable: 0, special: 0, depth: 0, lines: ["2 file(s) over 256 KiB not read (MANDU_WORKSPACE_SCAN_FILE_MAX_KB)"] },
  limits: { fileMaxBytes: 262_144, totalMaxBytes: 67_108_864, maxFiles: 20_000, timeoutMs: 30_000 },
  ms: 310,
  ...over,
});

function result(over: Partial<SuggestPolicyWire> = {}): SuggestPolicyWire {
  return {
    axis: true, running: false, suggestions: [view(), blobView()], filed: ["pp-000001", "pp-000002"],
    covered: [{ repoRoot: REPO, paths: ["protected.txt"], blobs: [], why: "protected-now" }],
    counts: { findings: 3, suggested: 2, filed: 2, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 1, dropped: 0, superseded: 0 },
    scan: { repos: [{ root: REPO, repoRoot: REPO }], counts: { blobs: 12, scanned: 12, classified: 3 }, capped: { lines: [] }, ms: 420 },
    ...over,
  };
}

interface Harness { deps: PolicySuggestDeps; out: string[]; err: string[]; applied: string[]; stops: number; calls: Array<{ roots: string[]; waitMs: number; opts?: SuggestOptsWire }> }

function harness(over: Partial<PolicySuggestDeps> & { keys?: string[]; lines?: string[]; tty?: boolean; kind?: "resident" | "throwaway"; axisOn?: boolean | null; answer?: SuggestPolicyWire } = {}): Harness {
  const h: Harness = { deps: undefined as unknown as PolicySuggestDeps, out: [], err: [], applied: [], stops: 0, calls: [] };
  const keys = [...(over.keys ?? [])];
  const lines = [...(over.lines ?? [])];
  h.deps = {
    arbiter: async () => ({ sock: "/run/a.sock", kind: over.kind ?? "resident", axisOn: over.axisOn ?? true, stop: async () => { h.stops++; } }),
    suggest: async (_s, roots, _h, waitMs, _t, opts) => { h.calls.push({ roots, waitMs, ...(opts !== undefined ? { opts } : {}) }); return over.answer ?? result(); },
    apply: async (_s, id): Promise<ApplySuggestionWire> => {
      h.applied.push(id);
      const v = [view(), blobView(), wsView()].find((x) => x.id === id)!;
      return v.applicable
        ? { applied: true, changeId: "pc-000009", suggestion: { ...v, status: "approved" } }
        : { applied: false, refused: "unsupported", problems: ["this Mandu cannot apply lock-blob yet; the suggestion stays pending"], suggestion: v };
    },
    cwd: () => REPO,
    isTTY: () => over.tty ?? true,
    readKey: async () => keys.shift() ?? "",
    readLine: async () => lines.shift() ?? "",
    now: () => 0,
    sleep: async () => {},
    out: (s) => h.out.push(s),
    err: (s) => h.err.push(s),
    // Pinned: this host's platform must not decide the wording under test
    // (the macOS review says a history rule holds on Linux only; below).
    platform: "linux",
    ...over,
  };
  return h;
}

const ENV = { HOME, NO_COLOR: "1" };

// ── flags and modes ──────────────────────────────────────────────────────────

test("flags: --dry-run, --json, --apply-all, --no-color, --root (repeatable, both spellings); errors for the rest", () => {
  const a = parsePolicySuggestArgs(["--dry-run", "--root", "a", "--root=b", "--no-color"]);
  assert.deepEqual({ ...a }, { dryRun: true, json: false, applyAll: false, noColor: true, home: false, roots: ["a", "b"], model: null, endpoint: null, yesSend: null, errors: [] });
  assert.equal(parsePolicySuggestArgs(["--json"]).json, true);
  assert.equal(parsePolicySuggestArgs(["--apply-all"]).applyAll, true);
  assert.equal(parsePolicySuggestArgs(["--home"]).home, true);
  assert.deepEqual(parsePolicySuggestArgs(["--root"]).errors, ["--root needs a directory"]);
  assert.match(parsePolicySuggestArgs(["--bogus"]).errors[0]!, /unknown option '--bogus'/);
  assert.match(parsePolicySuggestArgs(["--apply-all", "--dry-run"]).errors[0]!, /contradict/);
  assert.match(parsePolicySuggestArgs(["--apply-all", "--json"]).errors[0]!, /pick one/);
  assert.match(parsePolicySuggestArgs(["--model", "t1"]).errors[0]!, /--model needs names or contents/);
  assert.deepEqual(parsePolicySuggestArgs(["--model", "contents"]).errors, [], "the contents tier is built (4c)");
});

test("modes: a terminal reviews interactively; none behaves as --dry-run and says so; --apply-all needs one", () => {
  const p = (r: string[]) => parsePolicySuggestArgs(r);
  assert.deepEqual(suggestMode(p([]), true), { mode: "interactive", note: null, refuse: null });
  const noTty = suggestMode(p([]), false);
  assert.equal(noTty.mode, "review");
  assert.match(noTty.note!, /as with --dry-run/);
  assert.equal(suggestMode(p(["--dry-run"]), true).mode, "review");
  assert.equal(suggestMode(p(["--json"]), false).mode, "json");
  assert.equal(suggestMode(p(["--apply-all"]), true).refuse, null);
  assert.match(suggestMode(p(["--apply-all"]), false).refuse!, /needs a terminal/);
});

// ── rendering ────────────────────────────────────────────────────────────────

test("a suggestion renders its rule, evidence (the mask as the scan made it), commits, impact and rotation advice", () => {
  const text = renderSuggestion(view(), 1, 2, { home: HOME, color: false });
  assert.equal(text, [
    "[1/2] Make ~/proj/deploy/id_ed25519 a secret no AI may read (only in git history)",
    "      in ~/proj · suggestion pp-000001",
    `      looks like a private key · ${PEM_MASK} (line 1)`,
    "      deploy/id_ed25519: added 11111111, removed or replaced 33333333",
    "      hides: every committed version of the file (1 old version found) · the working tree is unchanged",
    "      This key was exposed. Rotate it: a rule keeps the AI from reading it from now on; it cannot undo a push or an earlier session.",
    "",
  ].join("\n"));
  // Nothing but the mask: no character after the header's ellipsis.
  assert.ok(!text.includes(PEM_MASK + "b"), "no body after the mask");
  const b = renderSuggestion(blobView(), 2, 2, { home: HOME, color: false });
  assert.match(b, /looks like a GitHub token · ghp_… \(line 2\)/);
  assert.match(b, /hides: 1 old version of config\.py · the current config\.py stays readable to the AI/);
  assert.match(renderSuggestion(view({ impact: { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/key"] } }), 1, 1, { home: HOME, color: false }),
    /and now deploy\/key \(the AI sees a placeholder in its place\)/);
});

test("color only when asked: bold sentence, yellow rotation line; plain text has no escape", () => {
  assert.ok(!renderSuggestion(view(), 1, 1, { home: HOME, color: false }).includes("\u001b"));
  const c = renderSuggestion(view(), 1, 1, { home: HOME, color: true });
  assert.ok(c.includes("\u001b[1m[1/1]"));
  assert.ok(c.includes("\u001b[33mThis key was exposed"));
});

test("wire strings are stripped of control characters (an escape in a committed file name cannot reach the terminal)", () => {
  assert.equal(clean("a\u001b[2Jb\u0007c\u009bd"), "a?[2Jb?c?d");
  const text = renderSuggestion(view({ sentence: "Make \u001b]0;pwned\u0007 a secret" }), 1, 1, { home: HOME, color: false });
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(text));
});

test("[p] shows the exact policy.yaml lines: paths: for lock-path, blobs: for lock-blob; odd paths are quoted", () => {
  assert.deepEqual(policyYamlLines(view()), ["paths:", `  - path: ${REPO}/deploy/id_ed25519`, "    level: no-model"]);
  assert.deepEqual(policyYamlLines(blobView()), [
    "blobs:", `  - id: sha1:${"b".repeat(40)}`, "    level: no-model", '    note: "found in history: config.py (11111111..33333333)"',
  ]);
  assert.equal(yamlScalar("/a/b c.txt"), "/a/b c.txt");
  assert.equal(yamlScalar("/a/#x: y"), JSON.stringify("/a/#x: y"));
  assert.equal(yamlScalar("/a/\\[1\\].env"), JSON.stringify("/a/\\[1\\].env"), "an escaped literal is quoted, its backslashes doubled");
});

test("the scan header: what was read, found, covered; dismissed and over-cap counts; a running scan says so", () => {
  const h = renderScanHeader(result({ counts: { ...result().counts, dismissed: 1, overCap: 2 } }), [REPO], HOME);
  assert.match(h, /^Scanned the git history of ~\/proj \(12 file versions read in 0\.4 s\): 3 possible keys found, 1 already covered\./);
  assert.match(h, /1 finding was marked "not a secret" in the dashboard before/);
  assert.match(h, /2 more not listed: at most 20 wait per repository/);
  assert.match(h, /✓ protected\.txt: covered \(the file is protected now\)/);
  assert.match(renderScanHeader(result({ running: true, scan: null }), [REPO], HOME), /still running in Mandu/);
  assert.match(renderScanHeader(result({ scan: { ...result().scan!, repos: [{ root: "/tmp/x", repoRoot: null, reason: "not a git repository" }] } }), ["/tmp/x"], HOME), /No git repository to scan under \/tmp\/x \(not a git repository\)/);
});

test("keys: a/s/p/?/q, EOF, ^C and ^D quit; anything else is other", () => {
  assert.equal(readReviewKey("a"), "apply");
  assert.equal(readReviewKey("A"), "apply");
  assert.equal(readReviewKey("s"), "skip");
  assert.equal(readReviewKey("p"), "policy");
  assert.equal(readReviewKey("?"), "help");
  assert.equal(readReviewKey("q"), "quit");
  assert.equal(readReviewKey(""), "quit");
  assert.equal(readReviewKey("\u0003"), "quit");
  assert.equal(readReviewKey("\u0004"), "quit");
  assert.equal(readReviewKey("\r"), "other");
  assert.equal(readReviewKey("x"), "other");
});

test("apply outcomes in plain words; covered closes, the rest fail", () => {
  assert.deepEqual(applyOutcome({ applied: true, changeId: "pc-1", suggestion: view() }), { applied: true, failed: false, line: "Applied (change pc-1; undo it in the dashboard, under Rule changes in Approvals)." });
  assert.equal(applyOutcome({ applied: false, refused: "covered", problems: [], suggestion: view() }).failed, false);
  for (const r of ["relaxes", "invalid", "stale", "unsupported"] as const) {
    assert.equal(applyOutcome({ applied: false, refused: r, problems: ["x"], suggestion: view() }).failed, true, r);
  }
});

// ── the command ──────────────────────────────────────────────────────────────

test("interactive: [p] then [a] applies the first; [?] then [s] skips the second (not applicable: skip only); the dismissal note is printed once", async () => {
  const h = harness({ keys: ["p", "a", "?", "a", "s"] });
  const code = await runPolicySuggest([], ENV, layout, h.deps);
  const text = h.out.join("");
  assert.equal(code, 0, text + h.err.join(""));
  assert.deepEqual(h.applied, ["pp-000001"], "only the first was applied; 'a' on the second is not offered");
  assert.equal(text.split(DISMISS_NOTE).length - 1, 1, "the dashboard note, once");
  assert.match(text, /applying it adds to policy\.yaml:\n {8}paths:\n {10}- path: \/home\/u\/proj\/deploy\/id_ed25519/);
  assert.match(text, /Applied \(change pc-000009; undo it in the dashboard, under Rule changes in Approvals\)\./);
  assert.match(text, /this Mandu cannot apply lock-blob yet/);
  assert.match(text, / {6}\[s\]kip {2}\[p\]olicy\.yaml lines {2}\[q\]uit {2}\[\?\] /, "skip only for the inapplicable one");
  assert.match(text, /press s, p, q or \?/, "'a' there is answered with the keys that work");
  assert.match(text, /a {2}apply: add the rule/);
  assert.match(text, /Applied 1, skipped 1\. 1 suggestion stays waiting/);
  assert.ok(!/not a secret \[|\[d\]ismiss|\[n\]ot a secret/i.test(text), "no dismiss key in the terminal");
  assert.equal(h.stops, 1);
});

test("interactive: q (or EOF) stops at once and leaves the rest waiting", async () => {
  const h = harness({ keys: ["q"] });
  assert.equal(await runPolicySuggest([], ENV, layout, h.deps), 0);
  assert.deepEqual(h.applied, []);
  assert.match(h.out.join(""), /Applied 0, skipped 0\. 2 suggestions stay waiting/);
  const e = harness({ keys: [] });
  assert.equal(await runPolicySuggest([], ENV, layout, e.deps), 0);
  assert.deepEqual(e.applied, []);
});

test("no terminal and no flag: the review only, as --dry-run, said so; no key is read, nothing applied", async () => {
  let read = 0;
  const h = harness({ tty: false, readKey: async () => { read++; return "a"; } });
  assert.equal(await runPolicySuggest([], ENV, layout, h.deps), 0);
  const text = h.out.join("");
  assert.match(text, /no terminal to ask on: showing the review only, as with --dry-run/);
  assert.match(text, /\[1\/2\] Make ~\/proj\/deploy\/id_ed25519/);
  assert.match(text, /\[2\/2\] Hide an old version of ~\/proj\/config\.py/);
  assert.equal(read, 0);
  assert.deepEqual(h.applied, []);
});

test("--dry-run on a terminal: the review, nothing asked or applied", async () => {
  const h = harness({ keys: ["a", "a"] });
  assert.equal(await runPolicySuggest(["--dry-run"], ENV, layout, h.deps), 0);
  assert.deepEqual(h.applied, []);
  assert.match(h.out.join(""), /Nothing was applied \(--dry-run\)/);
});

test("--json: the suggestions and counts, no prompt, no header text", async () => {
  const h = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--json"], ENV, layout, h.deps), 0);
  const j = JSON.parse(h.out.join("")) as { suggestions: SuggestionViewWire[]; canApply: boolean; arbiter: string; counts: { findings: number } };
  assert.deepEqual(j.suggestions.map((s) => s.id), ["pp-000001", "pp-000002"]);
  assert.equal(j.canApply, true);
  assert.equal(j.arbiter, "resident");
  assert.equal(j.counts.findings, 3);
});

test("--apply-all without a terminal is refused before any scan or arbiter", async () => {
  let asked = 0;
  const h = harness({ tty: false, arbiter: async () => { asked++; throw new Error("not reached"); } });
  assert.equal(await runPolicySuggest(["--apply-all"], ENV, layout, h.deps), 2);
  assert.match(h.err.join(""), /--apply-all needs a terminal to confirm on/);
  assert.equal(asked, 0);
  assert.deepEqual(h.applied, []);
});

test("--apply-all on a terminal: one typed confirmation, then every applicable suggestion; a wrong answer applies nothing", async () => {
  const no = harness({ lines: ["y"] });
  assert.equal(await runPolicySuggest(["--apply-all"], ENV, layout, no.deps), 0);
  assert.deepEqual(no.applied, []);
  assert.match(no.out.join(""), /Not confirmed; nothing applied/);
  const yes = harness({ lines: ["apply"] });
  assert.equal(await runPolicySuggest(["--apply-all"], ENV, layout, yes.deps), 0);
  assert.deepEqual(yes.applied, ["pp-000001"], "the lock-blob one this Mandu cannot apply is skipped");
  assert.match(yes.out.join(""), /Applied 1, skipped 1\./);
});

test("a throwaway arbiter scans and shows, but applying is refused (--apply-all) or not offered (interactive)", async () => {
  const all = harness({ kind: "throwaway", axisOn: true, lines: ["apply"] });
  assert.equal(await runPolicySuggest(["--apply-all"], ENV, layout, all.deps), 1);
  assert.match(all.err.join(""), /--apply-all refused: no Mandu service is running, so a temporary one scanned/);
  assert.equal(all.stops, 1, "the throwaway is stopped");
  const i = harness({ kind: "throwaway", axisOn: false, keys: ["a", "s", "s"] });
  assert.equal(await runPolicySuggest([], ENV, layout, i.deps), 0);
  const text = i.out.join("");
  assert.deepEqual(i.applied, []);
  assert.match(text, /secret protection off \(see `mandu mode`\), so a temporary one scanned/);
  assert.ok(!text.includes("[a]pply"), "apply is not offered");
});

test("roots: --root resolves against the cwd and ~; a running scan is waited out, then only this repository's suggestions show", async () => {
  let n = 0;
  const other = view({ id: "pp-000077", repoRoot: "/elsewhere/repo" });
  const h = harness({
    tty: false,
    suggest: async (_s, roots, _h, waitMs) => {
      h.calls.push({ roots, waitMs });
      n++;
      return n === 1 ? result({ running: true, scan: null, suggestions: [other, view()] }) : result({ running: true, scan: null, suggestions: [other, view()] });
    },
  });
  let t = 0;
  h.deps.now = () => (t += 50_000);
  assert.equal(await runPolicySuggest(["--root", "sub", "--root", "~/x", "--json"], ENV, layout, h.deps), 0);
  assert.deepEqual(h.calls[0]!.roots, [`${REPO}/sub`, `${HOME}/x`]);
  const j = JSON.parse(h.out.join("")) as { suggestions: SuggestionViewWire[]; running: boolean };
  assert.equal(j.running, true);
  assert.deepEqual(j.suggestions.map((s) => s.id), ["pp-000001"], "the other repository's pending one is not listed");
});

test("errors: no arbiter, a failed scan (an older arbiter named), the axis off", async () => {
  const a = harness({ arbiter: async () => { throw new Error("socket gone"); } });
  assert.equal(await runPolicySuggest(["--dry-run"], ENV, layout, a.deps), 1);
  assert.match(a.err.join(""), /no Mandu service could run the scan \(socket gone\)/);
  const b = harness({ suggest: async () => { throw new Error("unknown op: suggestPolicy"); } });
  assert.equal(await runPolicySuggest(["--dry-run"], ENV, layout, b.deps), 1);
  assert.match(b.err.join(""), /older than this command/);
  assert.equal(b.stops, 1);
  const c = harness({ answer: result({ axis: false }) });
  assert.equal(await runPolicySuggest(["--dry-run"], ENV, layout, c.deps), 1);
  assert.match(c.err.join(""), /secret protection off; nothing was scanned/);
});

test("mandu policy: only `suggest`; anything else is a usage error", async () => {
  const h = harness();
  assert.equal(await runPolicy([], ENV, layout, h.deps), 2);
  assert.equal(await runPolicy(["apply"], ENV, layout, h.deps), 2);
  assert.match(h.err.join(""), /unknown command 'apply'/);
  assert.equal(await runPolicy(["suggest", "--bogus"], ENV, layout, h.deps), 2);
});

// ── the launch notice ────────────────────────────────────────────────────────

test("launch config: on by default with 1500 ms; MANDU_SUGGEST_AT_LAUNCH=0 turns it off; MANDU_SUGGEST_WAIT_MS sets the budget", () => {
  assert.deepEqual(launchSuggestConfig({}), { enabled: true, waitMs: 1500 });
  assert.equal(launchSuggestConfig({ MANDU_SUGGEST_AT_LAUNCH: "0" }).enabled, false);
  assert.equal(launchSuggestConfig({ MANDU_SUGGEST_AT_LAUNCH: "off" }).enabled, false);
  assert.equal(launchSuggestConfig({ MANDU_SUGGEST_WAIT_MS: "300" }).waitMs, 300);
  assert.equal(launchSuggestConfig({ MANDU_SUGGEST_WAIT_MS: "banana" }).waitMs, 1500);
  assert.equal(launchSuggestConfig({ MANDU_SUGGEST_WAIT_MS: "99999999" }).waitMs, 1500);
});

test("launch notice: one line counting this project's pending suggestions; none, another repo's or the axis off → nothing", () => {
  assert.equal(launchSuggestionNotice(result(), REPO),
    "mandu: 2 possible keys in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
  assert.equal(launchSuggestionNotice(result({ suggestions: [view()] }), `${REPO}/src`),
    "mandu: 1 possible key in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
  // The compact launch display's short form of the same notice (launch-banner.ts).
  assert.equal(compactNotice(launchSuggestionNotice(result(), REPO)!),
    "mandu: ! 2 possible keys in this project are not protected; see `mandu policy suggest`");
  assert.equal(launchSuggestionNotice(result({ suggestions: [] }), REPO), null);
  assert.equal(launchSuggestionNotice(result({ suggestions: [view({ repoRoot: "/other", edits: [{ op: "lock-path", path: "/other/deploy/id_ed25519", level: "no-model" }] })] }), REPO), null);
  assert.equal(launchSuggestionNotice(result({ suggestions: [view({ repoRoot: `${REPO}-two`, edits: [{ op: "lock-path", path: `${REPO}-two/deploy/id_ed25519`, level: "no-model" }] })] }), REPO), null, "a sibling with a common prefix is not this repository");
  assert.equal(launchSuggestionNotice(result({ axis: false }), REPO), null);
  assert.equal(launchSuggestionNotice(null, REPO), null);
  assert.deepEqual(suggestionsFor([view({ status: "approved" })], [REPO]), []);
});

test("launch: asks with the budget, answers the notice; a running scan answers what is pending", async () => {
  const seen: Array<{ waitMs: number; timeoutMs: number; roots: string[] }> = [];
  const line = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "200" } }, {
    suggest: async (_s, roots, _h, waitMs, timeoutMs) => { seen.push({ waitMs, timeoutMs, roots }); return result({ running: true, scan: null, suggestions: [view()] }); },
  });
  assert.deepEqual(seen, [{ waitMs: 200, timeoutMs: 200 + LAUNCH_SUGGEST_MARGIN_MS, roots: [REPO] }]);
  assert.match(line!, /^mandu: 1 possible key/);
});

test("launch: never rejects, never waits past budget + margin (a wedged arbiter), errors are debug only; off = no call", async () => {
  const debug: string[] = [];
  const t0 = Date.now();
  const wedged = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "100" } }, {
    suggest: () => new Promise(() => { /* never answers */ }), debug: (m) => debug.push(m),
  });
  const took = Date.now() - t0;
  assert.equal(wedged, null);
  assert.ok(took < 100 + LAUNCH_SUGGEST_MARGIN_MS + 400, `took ${took} ms`);
  assert.match(debug[0]!, /not checked \(no answer within the budget\)/);
  const failed = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: {} }, {
    suggest: async () => { throw new Error("unknown op"); }, debug: (m) => debug.push(m),
  });
  assert.equal(failed, null);
  assert.match(debug[1]!, /not checked \(unknown op\)/);
  const thrown = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: {} }, {
    suggest: () => { throw new Error("sync"); }, debug: (m) => debug.push(m),
  });
  assert.equal(thrown, null);
  let called = 0;
  assert.equal(await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_AT_LAUNCH: "0" } }, {
    suggest: async () => { called++; return result(); },
  }), null);
  assert.equal(called, 0);
});

test("launch: an arbiter that answers running:true at once adds no wait beyond its answer", async () => {
  const t0 = Date.now();
  const line = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "1500" } }, {
    suggest: async () => result({ running: true, scan: null, suggestions: [] }),
  });
  assert.equal(line, null);
  assert.ok(Date.now() - t0 < 200, "resolved with the answer, not at the budget");
});

// ── §5.5: the earlier scan's result (launch speed) ──────────────────────────

test("launch: every call asks answerFromEarlier, with the budget for a workspace scanned never before", async () => {
  const seen: Array<SuggestOptsWire | undefined> = [];
  await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "300" } }, {
    suggest: async (_s, _r, _h, _w, _t, opts) => { seen.push(opts); return result(); },
  });
  assert.deepEqual(seen, [{ answerFromEarlier: true }]);
});

test("launch notice: an earlier scan's result says so after the advice; the compact form is unchanged; a fresh one or a first running one does not", () => {
  const earlier = launchSuggestionNotice(result({ running: true, scan: null, lastScanAt: 1_700_000_000_000 }), REPO)!;
  assert.equal(earlier,
    "mandu: 2 possible keys in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard" + EARLIER_SCAN_NOTE);
  assert.match(earlier, /\(from the last finished scan; a new one is running\)$/);
  assert.equal(compactNotice(earlier), "mandu: ! 2 possible keys in this project are not protected; see `mandu policy suggest`");
  // Finished now (its own time), or still running with no scan before (a first launch past its budget): no note.
  assert.doesNotMatch(launchSuggestionNotice(result({ lastScanAt: 1_700_000_000_000 }), REPO)!, /last finished scan/);
  assert.doesNotMatch(launchSuggestionNotice(result({ running: true, scan: null, lastScanAt: null }), REPO)!, /last finished scan/);
  assert.doesNotMatch(launchSuggestionNotice(result({ running: true, scan: null }), REPO)!, /last finished scan/, "an older arbiter");
  assert.equal(fromEarlierScan(result({ running: true, lastScanAt: 5 })), true);
  assert.equal(fromEarlierScan(result({ running: false, lastScanAt: 5 })), false);
  assert.equal(launchSuggestionNotice(result({ running: true, lastScanAt: 5, suggestions: [] }), REPO), null, "nothing waits: no line, earlier or not");
});

test("launch: no earlier result → waits for the scan within the budget; an earlier result → the notice at once, no wait", async () => {
  // The arbiter's two answers (arbiter server.ts suggestPolicyOp): a first
  // scan is waited for (up to the budget); after one finished it answers at
  // once from that result while this scan runs on in the arbiter.
  let finished: number | null = null;
  const arbiter = (_s: string, _r: string[], _h: string, waitMs: number, _t: number, opts?: SuggestOptsWire): Promise<SuggestPolicyWire> => {
    if (opts?.answerFromEarlier === true && finished !== null) {
      return Promise.resolve(result({ running: true, scan: null, suggestions: [view()], lastScanAt: finished }));
    }
    const scanMs = 150;
    return new Promise((res) => setTimeout(() => {
      if (scanMs <= waitMs) { finished = Date.now(); res(result({ suggestions: [view()], lastScanAt: finished })); }
      else res(result({ running: true, scan: null, suggestions: [], lastScanAt: null }));
    }, Math.min(scanMs, waitMs)));
  };
  let t0 = Date.now();
  const first = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "1500" } }, { suggest: arbiter });
  const firstMs = Date.now() - t0;
  assert.ok(firstMs >= 140, `the first launch waited for the scan (${firstMs} ms)`);
  assert.equal(first, "mandu: 1 possible key in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
  t0 = Date.now();
  const debug: string[] = [];
  const second = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "1500" } }, { suggest: arbiter, debug: (m) => debug.push(m) });
  const secondMs = Date.now() - t0;
  assert.ok(secondMs < 100, `the second launch did not wait (${secondMs} ms)`);
  assert.equal(second, first + EARLIER_SCAN_NOTE);
  assert.match(debug.join("\n"), /from the last finished scan; this launch's scan runs in the background/);
});

test("launch: a first scan longer than the budget is cut at the budget (bounded), and the scan's error is one debug note", async () => {
  const t0 = Date.now();
  const cut = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "100" } }, {
    // The arbiter answers `running: true` at the budget, nothing pending yet.
    suggest: (_s, _r, _h, waitMs) => new Promise((res) => setTimeout(() => res(result({ running: true, scan: null, suggestions: [], lastScanAt: null })), waitMs)),
  });
  const took = Date.now() - t0;
  assert.equal(cut, null);
  assert.ok(took >= 90 && took < 100 + LAUNCH_SUGGEST_MARGIN_MS, `took ${took} ms`);
  const debug: string[] = [];
  const failed = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: {} }, {
    suggest: async () => { throw new Error("suggestPolicy: answerFromEarlier must be a boolean"); }, debug: (m) => debug.push(m),
  });
  assert.equal(failed, null);
  assert.deepEqual(debug, ["mandu: policy suggestions not checked (suggestPolicy: answerFromEarlier must be a boolean)"]);
});

test("launch: once settled it reports nothing more (a late failure never reaches the agent's terminal)", async () => {
  const debug: string[] = [];
  let fail!: (e: Error) => void;
  const line = await startLaunchSuggest({ sock: "/s", cwd: REPO, home: HOME, env: { MANDU_SUGGEST_WAIT_MS: "50" } }, {
    // A call with no deadline of its own: the cap settles the wait; the
    // failure arrives after.
    suggest: () => new Promise((_res, rej) => { fail = rej; }), debug: (m) => debug.push(m),
  });
  assert.equal(line, null);
  assert.equal(debug.length, 1);
  fail(new Error("late"));
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(debug, ["mandu: policy suggestions not checked (no answer within the budget)"]);
});

// ── the workspace scan (plan 14 §13.6) ───────────────────────────────────────

test("a workspace suggestion renders its hit (mask and line), no commit line, 'hides: this file, from the next launch' and the softer rotation line", () => {
  const text = renderSuggestion(wsView(), 3, 3, { home: HOME, color: false });
  assert.equal(text, [
    "[3/3] Make ~/proj/deploy/staging.conf a secret no AI may read",
    "      in ~/proj · suggestion pp-000003",
    "      looks like a GitHub token · ghp_… (line 2)",
    `      ${WORKSPACE_IMPACT_LINE}`,
    `      ${WORKSPACE_ROTATE_LINE}`,
    "",
  ].join("\n"));
  assert.equal(WORKSPACE_IMPACT_LINE, "hides: this file, from the next launch");
  assert.equal(WORKSPACE_ROTATE_LINE, "If an AI session read this file before, rotate the key.");
  assert.ok(!/added|removed|commit not traced|This key was exposed/.test(text), "no commit line and no exposure claim");
  // Many hits: two shown, the rest counted; a control character in a wire
  // string cannot reach the terminal.
  const d = wsView().evidence.findings[0]!.detectors[0]!;
  const many = renderSuggestion(wsView({
    sentence: "Make \u001b]0;x\u0007 a secret",
    evidence: { ...wsView().evidence, findings: [{ ...wsView().evidence.findings[0]!, detectors: [d, { ...d, line: 5 }, { ...d, line: 9, mask: "ghp_…\u009b2J" }] }] },
  }), 1, 1, { home: HOME, color: false });
  assert.match(many, /\(line 5\)\n {6}\+1 more hit in this file\n/);
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(many));
  // The policy.yaml lines are the ordinary path lock.
  assert.deepEqual(policyYamlLines(wsView()), ["paths:", `  - path: ${REPO}/deploy/staging.conf`, "    level: no-model"]);
});

test("the header names both scans, with each scan's caps in plain words; a home root says configuration files only", () => {
  const h = renderScanHeader(result({ workspaceScan: wsScan(), counts: { ...result().counts, findings: 4 } }), [REPO], HOME);
  assert.match(h, /^Scanned the git history of ~\/proj \(12 file versions read in 0\.4 s\) and 1,204 files in ~\/proj \(38 read, 1,160 unchanged since the last scan, 6 already protected, not opened, in 0\.3 s\): 4 possible keys found, 1 already covered\.\n/);
  assert.match(h, / {2}· not scanned: 2 file\(s\) over 256 KiB not read \(MANDU_WORKSPACE_SCAN_FILE_MAX_KB\)/);
  const home = workspaceScanPhrase(wsScan({ roots: [{ root: REPO, tier: "workspace" }, { root: HOME, tier: "home" }, { root: "/proc/1", tier: "workspace", reason: "a kernel pseudo-filesystem" }], counts: { examined: 1, read: 1, cached: 0, bytes: 10, covered: 0 } }), HOME);
  assert.equal(home, "1 file in ~/proj, ~ (configuration files only) (1 read, in 0.3 s)");
  const reasons = renderScanHeader(result({ workspaceScan: wsScan({ roots: [{ root: REPO, tier: "workspace" }, { root: "/proc/1", tier: "workspace", reason: "a kernel pseudo-filesystem" }] }) }), [REPO, "/proc/1"], HOME);
  assert.match(reasons, / {2}· not scanned: \/proc\/1 \(a kernel pseudo-filesystem\)/);
  // A folder that is no repository: the files are still scanned, and the
  // header says there was no history.
  const noRepo = renderScanHeader(result({
    scan: { ...result().scan!, repos: [{ root: "/tmp/x", repoRoot: null, reason: "not a git repository" }] },
    workspaceScan: wsScan({ roots: [{ root: "/tmp/x", tier: "workspace" }], counts: { examined: 3, read: 3, cached: 0, bytes: 30, covered: 0 } }),
  }), ["/tmp/x"], HOME);
  assert.match(noRepo, /^Scanned 3 files in \/tmp\/x \(3 read, in 0\.3 s\): 3 possible keys found/);
  assert.match(noRepo, / {2}· no git history scanned: not a git repository/);
  // Neither walked: one line with the reason.
  assert.match(renderScanHeader(result({ scan: null, workspaceScan: wsScan({ roots: [{ root: "rel", tier: "workspace", reason: "not an absolute path" }] }) }), ["rel"], HOME),
    /^No git repository or folder to scan under rel \(not an absolute path\)\./);
  // An older arbiter (no workspaceScan): the history header as before.
  const { workspaceScan: _omit, ...older } = result();
  assert.match(renderScanHeader(older as SuggestPolicyWire, [REPO], HOME), /^Scanned the git history of ~\/proj \(12 file versions read in 0\.4 s\): 3 possible keys found/);
});

test("--home sends includeHome (the home tier) and names it; without it the call asks for no home tier; the budget covers both scans", async () => {
  const h = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--home", "--dry-run"], ENV, layout, h.deps), 0);
  assert.deepEqual(h.calls[0]!.opts, { includeHome: true, countLabels: true });
  assert.match(h.out.join(""), /^Scanning the git history and the files of ~\/proj, and your home folder's configuration files …\n/);
  const n = harness({ tty: false });
  assert.equal(await runPolicySuggest(["--dry-run"], ENV, layout, n.deps), 0);
  assert.deepEqual(n.calls[0]!.opts, { countLabels: true }, "an explicit scan counts the sensitivity labels (plan 14 §14.1)");
  assert.match(n.out.join(""), /^Scanning the git history and the files of ~\/proj …\n/);
  assert.equal(n.calls[0]!.waitMs, suggestCallBudgetMs(ENV));
  assert.equal(suggestCallBudgetMs({}), 60_000 + 30_000 + 30_000);
  assert.equal(suggestCallBudgetMs({ MANDU_HISTORY_SCAN_TIMEOUT_S: "10", MANDU_WORKSPACE_SCAN_TIMEOUT_S: "5" }), 10_000 + 30_000 + 5_000);
});

test("the production suggest sends includeHome only when asked, and never `sources` (both scans run)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-ps-wire-"));
  const sock = join(dir, "s.sock");
  const seen: Array<Record<string, unknown>> = [];
  const srv = createServer((c) => {
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl)) as Record<string, unknown>;
      seen.push(req);
      c.end(JSON.stringify({ id: req["id"], ok: true, result: result() }) + "\n");
    });
  });
  await new Promise<void>((r) => srv.listen(sock, r));
  try {
    const d = realPolicySuggestDeps();
    await d.suggest(sock, [REPO], HOME, 100, 5000, { includeHome: true, countLabels: true });
    await d.suggest(sock, [REPO], HOME, 100, 5000);
    assert.equal(seen[0]!["op"], "suggestPolicy");
    assert.equal(seen[0]!["includeHome"], true);
    assert.equal(seen[0]!["home"], HOME);
    assert.equal("includeHome" in seen[1]!, false);
    assert.equal(seen[0]!["countLabels"], true);
    assert.equal("countLabels" in seen[1]!, false, "the launch's call (no opts) never asks to count");
    assert.equal("sources" in seen[0]! || "sources" in seen[1]!, false);
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--json carries workspaceScan and the workspace suggestion; DEL and C1 controls are escaped and it still parses", async () => {
  const h = harness({ tty: false, answer: result({ suggestions: [view(), blobView(), wsView({ sentence: "Make a\u009b2Jb a secret" })], workspaceScan: wsScan() }) });
  assert.equal(await runPolicySuggest(["--json"], ENV, layout, h.deps), 0);
  const text = h.out.join("");
  assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(text), "no raw control character");
  const j = JSON.parse(text) as { suggestions: SuggestionViewWire[]; workspaceScan: WorkspaceScanWire; includeHome: boolean };
  assert.equal(j.workspaceScan.counts.examined, 1204);
  assert.equal(j.includeHome, false);
  const ws = j.suggestions.find((s) => s.source === "workspace")!;
  assert.equal(ws.sentence, "Make a\u009b2Jb a secret", "the value round-trips");
  assert.equal(jsonText({ a: "\u007f" }), '{\n  "a": "\\u007f"\n}');
  // An older arbiter: workspaceScan null, not absent.
  const { workspaceScan: _omit, ...older } = result();
  const o = harness({ tty: false, answer: older as SuggestPolicyWire });
  assert.equal(await runPolicySuggest(["--json"], ENV, layout, o.deps), 0);
  assert.equal((JSON.parse(o.out.join("")) as { workspaceScan: unknown }).workspaceScan, null);
});

test("interactive over a workspace suggestion: [p] shows the paths: lines, [a] applies it like a history one", async () => {
  const h = harness({ keys: ["p", "a"], answer: result({ suggestions: [wsView()], workspaceScan: wsScan() }) });
  assert.equal(await runPolicySuggest([], ENV, layout, h.deps), 0);
  const text = h.out.join("");
  assert.deepEqual(h.applied, ["pp-000003"]);
  assert.match(text, /\[1\/1\] Make ~\/proj\/deploy\/staging\.conf a secret no AI may read\n/);
  assert.match(text, /paths:\n {10}- path: \/home\/u\/proj\/deploy\/staging\.conf\n {10} {2}level: no-model/);
  assert.match(text, /Applied \(change pc-000009;/);
});

test("launch notice: a workspace suggestion counts when its repository holds the cwd or its path lies under it; a sibling's does not", () => {
  // The scan root is the cwd, which is no repository: repoRoot = the cwd.
  assert.match(launchSuggestionNotice(result({ suggestions: [wsView()] }), REPO)!, /^mandu: 1 possible key in this project is not protected/);
  // A work tree below the cwd (the launch from a parent folder).
  const nested = wsView({ repoRoot: `${REPO}/svc`, edits: [{ op: "lock-path", path: `${REPO}/svc/deploy/staging.conf`, level: "no-model" }] });
  assert.match(launchSuggestionNotice(result({ suggestions: [nested] }), REPO)!, /^mandu: 1 possible key/);
  // A path under the cwd, whatever repoRoot says.
  const odd = wsView({ repoRoot: "/elsewhere", edits: [{ op: "lock-path", path: `${REPO}/a/token.txt`, level: "no-model" }] });
  assert.equal(suggestionsFor([odd], [REPO]).length, 1);
  // History and workspace together.
  assert.match(launchSuggestionNotice(result({ suggestions: [view(), wsView()] }), REPO)!, /^mandu: 2 possible keys in this project are not protected/);
  // A sibling folder with a common prefix, and an approved one.
  const sib = wsView({ repoRoot: `${REPO}-two`, edits: [{ op: "lock-path", path: `${REPO}-two/deploy/staging.conf`, level: "no-model" }] });
  assert.equal(launchSuggestionNotice(result({ suggestions: [sib] }), REPO), null);
  assert.equal(launchSuggestionNotice(result({ suggestions: [wsView({ status: "approved" })] }), REPO), null);
});

// ── plan 14 §14.1: sensitivity labels (S4) ───────────────────────────────────

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";

/** A sensitivity-label suggestion as the arbiter builds it. */
const labelView = (over: Partial<SuggestionViewWire> = {}): SuggestionViewWire => view({
  id: "pp-000004", source: "sensitivity-label", findingKey: `sensitivity-label:${REPO}/board/q3-board.docx`,
  edits: [{ op: "lock-path", path: `${REPO}/board/q3-board.docx`, level: "no-model" }],
  sentence: "Make ~/proj/board/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential",
  evidence: { paths: ["board/q3-board.docx"], blobs: [], findings: [], historyOnly: false, label: { id: HC, site: null, name: "Highly Confidential", level: "no-model" } },
  impact: { historicalVersions: 0, workingTreeChanges: true, files: ["board/q3-board.docx"] },
  historyOnly: false, rotate: false, humanOnly: false, applicable: true, createdAt: 3,
  ...over,
});
const humanView = (): SuggestionViewWire => labelView({
  id: "pp-000005", findingKey: `sensitivity-label:${REPO}/budget.xlsx`,
  edits: [{ op: "lock-path", path: `${REPO}/budget.xlsx`, level: "any-model" }],
  sentence: "Make ~/proj/budget.xlsx a secret any AI may read when it asks: its sensitivity label is Confidential",
  evidence: { paths: ["budget.xlsx"], blobs: [], findings: [], historyOnly: false, label: { id: HC, site: null, name: "Confidential", level: "any-model", adminFile: "/etc/mandu/policy.d/10-org.yaml" } },
  humanOnly: true,
});

test("§14.1: a sensitivity-label screen: the source words and the mapping's name, what it hides, no rotation line; control characters stripped", () => {
  assert.equal(renderSuggestion(labelView(), 1, 2, { home: HOME, color: false }), [
    "[1/2] Make ~/proj/board/q3-board.docx a secret no AI may read: its sensitivity label is Highly Confidential",
    "      in ~/proj · suggestion pp-000004",
    `      ${LABEL_SOURCE_LINE}: Highly Confidential`,
    `      ${WORKSPACE_IMPACT_LINE}`,
    `      ${LABEL_LOWER_LINE}`,
    "",
  ].join("\n"));
  assert.equal(LABEL_SOURCE_LINE, "From the document's sensitivity label");
  // §14.1: the review says a label lowered in Office later lowers nothing.
  assert.match(LABEL_LOWER_LINE, /lowered or removed in Office later, this rule stays as it is/);
  assert.doesNotMatch(renderSuggestion(wsView(), 1, 1, { home: HOME, color: false }), /in Office later/,
    "only a label's screen says it");
  const human = renderSuggestion(humanView(), 2, 2, { home: HOME, color: false });
  assert.match(human, /From the document's sensitivity label: Confidential \(mapped by your administrator\)/);
  assert.ok(!human.includes(HUMAN_ONLY_LINE), "said once, by the review under the screen (whyNotApplicable)");
  assert.doesNotMatch(human, /[Rr]otate/);
  const evil = renderSuggestion(labelView({ evidence: { ...labelView().evidence, label: { id: HC, site: null, name: "a\u001b[2Jb", level: "no-model" } } }), 1, 1, { home: HOME, color: false });
  assert.ok(!evil.includes("\u001b"));
  assert.deepEqual(policyYamlLines(labelView()), ["paths:", `  - path: ${REPO}/board/q3-board.docx`, "    level: no-model"]);
  assert.equal(whyNotApplicable(labelView()), null);
  assert.equal(whyNotApplicable(humanView()), HUMAN_ONLY_LINE);
  assert.match(HUMAN_ONLY_LINE, /only you can approve this level, in the dashboard/);
  // An older arbiter sends no humanOnly: an ordinary suggestion.
  const { humanOnly: _h, ...older } = labelView();
  assert.equal(whyNotApplicable(older as SuggestionViewWire), null);
});

test("§14.1: the launch notice names a labelled document as such, beside the keys", () => {
  assert.equal(launchSuggestionNotice(result({ suggestions: [labelView()] }), REPO),
    "mandu: 1 labelled document in this project is not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
  assert.equal(launchSuggestionNotice(result({ suggestions: [view(), labelView(), humanView()] }), REPO),
    "mandu: 1 possible key and 2 labelled documents in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard");
  assert.equal(launchSuggestionNotice(result({ suggestions: [view(), wsView()] }), REPO),
    "mandu: 2 possible keys in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard", "unchanged without a label");
});

test("§14.1: the header counts the labelled Office files and the ones nobody mapped", () => {
  const labels = { mode: "count" as const, examined: 20, read: 18, cached: 0, covered: 2, files: 14, mapped: 2, unmappedFiles: 12, unmapped: [{ id: HC, site: null, files: 12 }], unmappedMore: 0, encrypted: 1, unreadable: 0 };
  const h = renderScanHeader(result({ workspaceScan: wsScan({ labels }) }), [REPO], HOME);
  assert.match(h, / {2}· 14 Office files carry a sensitivity label \(2 mapped in your policy\)/);
  assert.match(h, / {2}· 12 files carry a sensitivity label you have not mapped: map it in the dashboard \(Settings › Sensitivity labels\) or under sensitivity_labels: in policy\.yaml/);
  const off = renderScanHeader(result({ workspaceScan: wsScan({ labels: { ...labels, mode: "off", files: 0, mapped: 0, unmappedFiles: 0, unmapped: [] } }) }), [REPO], HOME);
  assert.doesNotMatch(off, /sensitivity label/);
  assert.doesNotMatch(renderScanHeader(result({ workspaceScan: wsScan() }), [REPO], HOME), /sensitivity label/, "an older arbiter sends no labels");
});

test("§14.1: the review offers Skip only for a humanOnly suggestion; --apply-all leaves it waiting", async () => {
  const answer = result({ suggestions: [labelView(), humanView()] });
  const h = harness({ keys: ["a", "a", "s"], answer });
  h.deps.apply = async (_s, id) => {
    h.applied.push(id);
    return { applied: true, changeId: "pc-000010", suggestion: { ...labelView(), status: "approved" } };
  };
  assert.equal(await runPolicySuggest([], ENV, layout, h.deps), 0);
  const text = h.out.join("");
  assert.deepEqual(h.applied, ["pp-000004"], "the humanOnly one is never sent to applySuggestion");
  assert.match(text, /\[s\]kip {2}\[p\]olicy\.yaml lines {2}\[q\]uit {2}\[\?\] a\n {6}press s, p, q or \?/);
  assert.match(text, /Applied 1, skipped 1\./);

  const all = harness({ lines: ["apply"], answer });
  all.deps.apply = async (_s, id) => {
    all.applied.push(id);
    return { applied: true, changeId: "pc-000011", suggestion: { ...labelView(), status: "approved" } };
  };
  assert.equal(await runPolicySuggest(["--apply-all"], ENV, layout, all.deps), 0);
  assert.deepEqual(all.applied, ["pp-000004"]);
  assert.match(all.out.join(""), /Applied 1, skipped 1\./);
});

// ── macOS: a history rule is enforced by a Linux launch only ─────────────────

test("macOS: a gone-path or lock-blob suggestion says it hides committed versions on Linux only; a protected file is unreadable, not a placeholder; a workspace one is unchanged", () => {
  const mac = { home: HOME, color: false, platform: "darwin" };
  const gone = renderSuggestion(view(), 1, 2, mac);
  assert.match(gone, /hides: every committed version of the file \(1 old version found\) \(on Linux\) · the working tree is unchanged/);
  assert.ok(gone.includes(`      ${MACOS_HISTORY_LINE}\n`), gone);
  // A rotate advice there never says a rule keeps the history from the AI.
  assert.equal(view().rotate, true);
  assert.ok(gone.includes(MACOS_ROTATE_LINE) && !gone.includes(ROTATE_LINE), gone);
  assert.ok(renderSuggestion(view(), 1, 2, { home: HOME, color: false, platform: "linux" }).includes(ROTATE_LINE));
  assert.match(MACOS_HISTORY_LINE, /only a Linux launch hides them/);
  const blob = renderSuggestion(blobView(), 2, 2, mac);
  assert.match(blob, /hides: 1 old version of config\.py \(on Linux\) · the current config\.py stays readable to the AI/);
  assert.ok(blob.includes(MACOS_HISTORY_LINE));
  assert.match(impactLine(view({ impact: { historicalVersions: 0, workingTreeChanges: true, files: ["deploy/key"] } }), "darwin"), /and now deploy\/key \(the AI cannot read it\)$/);
  assert.equal(hidesHistory(view()), true);
  assert.equal(hidesHistory(wsView()), false);
  const ws = renderSuggestion(wsView(), 1, 1, mac);
  assert.ok(ws.includes(WORKSPACE_IMPACT_LINE) && !ws.includes(MACOS_HISTORY_LINE), "a workspace suggestion promises only the file, which macOS does make unreadable");
  // A sensitivity-label suggestion (§14.1) locks the document, no history: no macOS line.
  assert.equal(hidesHistory(labelView()), false);
  assert.ok(!renderSuggestion(labelView(), 1, 1, mac).includes(MACOS_HISTORY_LINE));
  assert.equal(hidesHistory(labelView({ source: "model-names" })), false);
  assert.equal(hidesHistory(labelView({ source: "model-contents" })), false);
  // Linux: the exact words as before (the pinned screen test above), no macOS line.
  assert.ok(!renderSuggestion(view(), 1, 1, { home: HOME, color: false }).includes("on Linux"));
  assert.ok(!renderSuggestion(view(), 1, 1, { home: HOME, color: false, platform: "linux" }).includes(MACOS_HISTORY_LINE));
});

test("macOS: the header's covered history finding is covered on Linux only; a covered workspace file is unchanged", () => {
  const r = result({ covered: [
    { repoRoot: REPO, paths: ["deploy/old.pem"], blobs: ["c".repeat(40)], why: "law" },
    { repoRoot: REPO, paths: ["protected.txt"], blobs: [], why: "protected-now" },
  ] });
  const mac = renderScanHeader(r, [REPO], HOME, "darwin");
  assert.match(mac, /✓ deploy\/old\.pem: covered \(your policy already hides it on Linux; on macOS its committed versions stay readable\)/);
  assert.match(mac, /✓ protected\.txt: covered \(the file is protected now\)\n/);
  const linux = renderScanHeader(r, [REPO], HOME);
  assert.match(linux, /✓ deploy\/old\.pem: covered \(your policy already hides it\)\n/);
});

test("macOS, interactive: applying a history suggestion says the rule holds on Linux launches only; applying a workspace one does not; Linux says neither", async () => {
  const answer = result({ suggestions: [view(), wsView()] });
  const mac = harness({ keys: ["a", "a"], platform: "darwin", answer });
  assert.equal(await runPolicySuggest([], ENV, layout, mac.deps), 0);
  const text = mac.out.join("");
  assert.deepEqual(mac.applied, ["pp-000001", "pp-000003"]);
  assert.ok(text.includes(`Applied (change pc-000009; undo it in the dashboard, under Rule changes in Approvals). ${MACOS_APPLIED_NOTE}\n`), text);
  assert.equal(text.split(MACOS_APPLIED_NOTE).length - 1, 1, "once: only the history suggestion");
  assert.ok(text.includes(MACOS_HISTORY_LINE), "the review screen says it too");
  const linux = harness({ keys: ["a", "a"], answer });
  await runPolicySuggest([], ENV, layout, linux.deps);
  assert.ok(!linux.out.join("").includes("macOS"), linux.out.join(""));
  // --apply-all on macOS: the same note after each history apply.
  const all = harness({ lines: ["apply"], platform: "darwin", answer });
  assert.equal(await runPolicySuggest(["--apply-all"], ENV, layout, all.deps), 0);
  assert.equal(all.out.join("").split(MACOS_APPLIED_NOTE).length - 1, 1);
});

test("macOS, the whole command: the scan header's covered history finding keeps its macOS words; applying a sensitivity-label suggestion adds no history note", async () => {
  const covered = [{ repoRoot: REPO, paths: ["deploy/old.pem"], blobs: ["c".repeat(40)], why: "law" as const }];
  const mac = harness({ keys: ["a"], platform: "darwin", answer: result({ covered, suggestions: [labelView()] }) });
  mac.deps.apply = async (_s, id) => { mac.applied.push(id); return { applied: true, changeId: "pc-000012", suggestion: { ...labelView(), status: "approved" } }; };
  assert.equal(await runPolicySuggest([], ENV, layout, mac.deps), 0);
  const text = mac.out.join("");
  assert.match(text, /deploy\/old\.pem: covered \(your policy already hides it on Linux; on macOS its committed versions stay readable\)/);
  assert.deepEqual(mac.applied, ["pp-000004"]);
  assert.ok(!text.includes(MACOS_APPLIED_NOTE) && !text.includes(MACOS_HISTORY_LINE), text);
  const linux = harness({ keys: ["a"], answer: result({ covered, suggestions: [labelView()] }) });
  linux.deps.apply = mac.deps.apply;
  await runPolicySuggest([], ENV, layout, linux.deps);
  assert.match(linux.out.join(""), /deploy\/old\.pem: covered \(your policy already hides it\)\n/);
});

// ── a held edit of policy.yaml (first-session tour 17, policy-surface.md §8.4.6) ──

import { closingLine, HELD_EDIT_LINE, refusedByHeldEdit } from "../../src/policy-suggest.js";

/** The arbiter's held-edit refusal, as `StalePolicyError(path, true)` words it
 *  (the stack test pins these words to the arbiter's own). */
const HELD_PROBLEM = "policy file /home/u/.mandu/policy.yaml holds a change made on disk that waits for a human in Approvals, and this change cannot be made to it as well (it names something that change removes or changes too); nothing was written. Decide that change first, then try again.";
const MOVED_PROBLEM = "policy file /home/u/.mandu/policy.yaml changed on disk since it was last loaded; the change on disk was loaded (or, if it relaxes the law, is waiting in Approvals) and nothing was written. Re-read the law and try again.";

test("a refusal by a held edit says what waits and where to answer it, never just 'Run this again'; a file that moved still says to run it again", () => {
  const held: ApplySuggestionWire = { applied: false, refused: "stale", problems: [HELD_PROBLEM], suggestion: view() };
  const moved: ApplySuggestionWire = { applied: false, refused: "stale", problems: [MOVED_PROBLEM], suggestion: view() };
  assert.equal(refusedByHeldEdit(held), true);
  assert.equal(refusedByHeldEdit(moved), false, "'is waiting in Approvals' about a moved file is not the held refusal");
  assert.equal(refusedByHeldEdit({ applied: false, refused: "invalid", problems: [HELD_PROBLEM], suggestion: view() }), false, "only a stale refusal");
  const o = applyOutcome(held);
  assert.deepEqual(o, { applied: false, failed: true, line: HELD_EDIT_LINE, held: true });
  assert.match(o.line, /waits for your OK on the dashboard's Approvals page/);
  assert.match(o.line, /Allow or Not now; `mandu dashboard` opens it/);
  assert.match(o.line, /then run `mandu policy suggest` again/);
  assert.match(o.line, /This suggestion stays waiting\./);
  assert.doesNotMatch(o.line, /Run this again|changed on disk meanwhile/);
  const m = applyOutcome(moved);
  assert.equal(m.held, undefined);
  assert.match(m.line, /policy\.yaml changed on disk meanwhile .*Run this again\.$/);
});

test("closingLine: with a held refusal, the last line names Approvals instead of 'run this again'; without one, unchanged", () => {
  assert.equal(closingLine({ total: 2, applied: 2, skipped: 0, failed: 0, held: 0 }), "Applied 2, skipped 0. Nothing is left waiting.\n");
  assert.equal(closingLine({ total: 2, applied: 1, skipped: 1, failed: 0, held: 0 }),
    "Applied 1, skipped 1. 1 suggestion stays waiting: run this again, or open Keys Mandu found in the dashboard.\n");
  const one = closingLine({ total: 2, applied: 0, skipped: 1, failed: 1, held: 1 });
  assert.equal(one, "Applied 0, skipped 1, 1 not applied. 2 suggestions stay waiting; one waits on the change to policy.yaml on the dashboard's Approvals page: answer that change there (`mandu dashboard`), then run `mandu policy suggest` again.\n");
  assert.match(closingLine({ total: 3, applied: 0, skipped: 0, failed: 3, held: 2 }), /; 2 wait on the change to policy\.yaml/);
  assert.doesNotMatch(one, /run this again/i);
});

test("interactive: a suggestion a held edit keeps out prints the held-edit line, ends naming Approvals, exits 1", async () => {
  const h = harness({
    keys: ["a", "s"],
    apply: async (_s, id) => { h.applied.push(id); return { applied: false, refused: "stale", problems: [HELD_PROBLEM], suggestion: view() }; },
  });
  const code = await runPolicySuggest([], ENV, layout, h.deps);
  const text = h.out.join("");
  assert.equal(code, 1, text);
  assert.ok(text.includes(`      ${HELD_EDIT_LINE}\n`), text);
  assert.match(text, /Applied 0, skipped 1, 1 not applied\. 2 suggestions stay waiting; one waits on the change to policy\.yaml on the dashboard's Approvals page: answer that change there \(`mandu dashboard`\), then run `mandu policy suggest` again\.\n$/);
  assert.doesNotMatch(text, /Run this again|run this again/);
});
