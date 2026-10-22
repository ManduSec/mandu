/**
 * suggestions — the Files and folders explorer's Suggested view
 * (confidentiality-plan-14-policy-suggestions.md §5.4, §13.6; dashboard.md
 * §4.25r): the arbiter's policy suggestions (`SuggestionView`, filed by
 * Mandu's git-history scan and its workspace scan) as the explorer's rows,
 * and a finished scan as one line. Pure; the routes
 * (server/suggestion-routes.ts) do the arbiter. Mandu-new (no reference
 * origin).
 *
 * One row per suggestion. A `lock-path` suggestion is a row on its path;
 * a path that exists only in git history is tagged so. A `lock-blob`
 * suggestion is a sub-row under the file as it is now ("2 old versions of
 * config.py"), since the current file keeps its label. A workspace
 * suggestion (`source: "workspace"`, plan 14 §13) is an ordinary file row:
 * no tag, no commits, the detector's line in the file, and the softer
 * rotation advice (nothing shows the key left the machine). A
 * sensitivity-label suggestion (`source: "sensitivity-label"`, plan 14
 * §14.1) is an ordinary file row too: "From the document's sensitivity
 * label", the MAPPING's name for the label (the person's or the
 * administrator's words, never the file's), the level the mapping gives it,
 * and no rotation advice (a label is not a key); and that a label lowered
 * or removed in Office later does not lower the rule Save writes. A model's
 * row (`model-names`, plan 14 §14.10; `model-contents`, §14.11) says
 * "Suggested by your model <name>" and the reason in the arbiter's words,
 * and what the model saw (names only, or the start of the file, read by
 * your own model). Everything shown
 * is what the arbiter's scan let out: paths, commit ids, the detector in
 * plain words, its line and its fixed mask. No field here carries a secret
 * value, and none is built from one.
 *
 * Platform-aware, as the terminal review is (launcher/src/policy-suggest.ts):
 * only a Linux launch hides committed versions (plan 14 §8, §11.1); a macOS
 * launch hides none (confidentiality.md §7.3, plan 14 §11.3). So on macOS a
 * history row's impact says the history part holds on Linux, and that the
 * committed versions stay readable there. A workspace row promises only the
 * file, which macOS does make unreadable: unchanged.
 */
import { posix } from "node:path";

import type { HomeTextPart } from "./ask-words.js";
import { tildePath } from "./file-browser.js";

// ── the wire (arbiter/ipc/protocol.ts SuggestionView), declared here so the
//    dashboard typechecks standalone ────────────────────────────────────────

export type SuggestionEditWire =
  | { op: "lock-path"; path: string; level: string; bindings?: string[]; recursive?: boolean }
  | { op: "lock-blob"; blob: string; level: string; note?: string };

export interface SuggestionDetectorWire {
  kind: "content-shape" | "catalog-path";
  rule: string;
  mask: string;
  words: string;
  line?: number;
  path?: string;
}

export interface SuggestionFindingWire {
  blob: string;
  paths: string[];
  firstCommit: string | null;
  lastCommit: string | null;
  inHead: boolean;
  inIndex: boolean;
  stillPresent: boolean;
  detectors: SuggestionDetectorWire[];
}

/** A sensitivity-label suggestion's evidence (plan 14 §14.1): the label's
 *  ids and the MAPPING's name and level, never the file's text. */
export interface SuggestionLabelWire {
  id: string;
  site: string | null;
  name: string;
  level: string;
  adminFile?: string;
}

export interface SuggestionWire {
  id: string;
  kind: "suggestion";
  status: "pending" | "approved" | "denied" | "superseded";
  requestedBy: string;
  findingKey: string;
  source: string;
  repoRoot: string;
  edits: SuggestionEditWire[];
  sentence: string;
  evidence: {
    paths: string[]; blobs: string[]; findings: SuggestionFindingWire[]; historyOnly: boolean; label?: SuggestionLabelWire;
    /** `source: "past-sessions"` only (plan 17 §3 item 13): the key names
     *  in the file and how many past sessions sent one to the AI. */
    pastSessions?: { names: string[]; sessions: number; last: string | null };
  };
  impact: { historicalVersions: number; workingTreeChanges: boolean; files: string[] };
  historyOnly: boolean;
  rotate: boolean;
  /** Plan 14 §14.1: only a person applies it (the admin channel, which is
   *  how Save applies every suggestion). Absent from an older arbiter. */
  humanOnly?: boolean;
  /** `source: "model-names"` / `"model-contents"` only (plan 14 §14.4,
   *  §14.11): the model's name and its answer as enums, with the arbiter's
   *  words for the reason. */
  model?: ModelFactsWire;
  applicable: boolean;
  createdAt: number;
  resolvedAt: number | null;
  resolvedBy: string | null;
  changeId: string | null;
  supersededBy: string | null;
}

/** A names-only model suggestion's facts (arbiter/policy/policy-model.ts
 *  ModelSuggestionFacts): enums and the arbiter's own words, never a string
 *  the model wrote. */
export interface ModelFactsWire {
  endpoint: string;
  level: string;
  reason: string;
  reasonWords: string;
  candidate: "file" | "folder";
  files: number;
  covers: string[];
}

/** The workspace scan's summary (arbiter/policy/secret-workspace-scan.ts
 *  SecretWorkspaceScanSummary), the fields the page reads. */
export interface WorkspaceScanWire {
  roots: Array<{ root: string; tier: "workspace" | "home"; reason?: string }>;
  counts: { examined: number; read: number; cached: number; bytes: number; covered: number };
  capped: {
    tooBig: number; overTotal: number; overTime: number; overFiles: number; binary: number;
    symlinks: number; unreadable: number; special?: number; depth: number; worktrees?: number; lines?: string[];
  };
  limits: { fileMaxBytes: number; totalMaxBytes: number; maxFiles: number; timeoutMs: number };
  ms: number;
  /** Plan 14 §14.1: what the label read did (absent from an older arbiter;
   *  null when it was not asked for). */
  labels?: LabelScanWire | null;
}

/** The label read's summary (arbiter/policy/sensitivity-labels.ts
 *  SensitivityLabelScanSummary), the fields the page reads. */
export interface LabelScanWire {
  /** `mapped`: a mapping is in force; `count`: none, but this scan counted;
   *  `off`: no Office file was opened. */
  mode: "mapped" | "count" | "off";
  examined: number;
  read: number;
  cached: number;
  covered: number;
  /** Files carrying an enabled label. */
  files: number;
  /** Of those, files with a mapped label. */
  mapped: number;
  /** Files carrying a label no mapping names. */
  unmappedFiles: number;
  unmapped: Array<{ id: string; site: string | null; files: number }>;
  unmappedMore: number;
  encrypted: number;
  unreadable: number;
  capped?: { overFiles: number; overBytes: number };
  /** The label read's own budgets (LabelScanLimits); absent from an older
   *  answer. */
  limits?: { maxFiles: number; totalMaxBytes: number };
}

/** `suggestPolicy`'s answer (arbiter/ipc/protocol.ts SuggestPolicyResult),
 *  the fields the page reads. */
export interface SuggestPolicyWire {
  axis: boolean;
  running: boolean;
  suggestions: SuggestionWire[];
  filed: string[];
  covered: unknown[];
  counts: {
    findings: number; suggested: number; filed: number; alreadyPending: number; dismissed: number;
    overCap: number; covered: number; dropped: number; superseded: number;
  };
  scan: {
    repos: Array<{ root: string; repoRoot: string | null; reason?: string }>;
    /** `readFailed`: blobs git failed to hand over before the deadline
     *  (absent from an arbiter that predates it). */
    capped: { tooBig: number; overTotal: number; overTime: number; readFailed?: number; untraced: number; unlisted: boolean; lines?: string[] };
    ms: number;
  } | null;
  /** The workspace scan (plan 14 §13.5); null when it did not run, absent
   *  from an arbiter that predates it. */
  workspaceScan?: WorkspaceScanWire | null;
}

// ── the rows ────────────────────────────────────────────────────────────────

/** One detector as the opened row says it: "Looks like a private key", and
 *  the scan's mask. */
export interface FoundVM {
  words: string;
  mask: string;
  /** A workspace finding: its line in the file as it is now. */
  line?: number;
}

export interface SuggestionRowVM {
  id: string;
  /** `path`: the row locks a file (a key in a file, or one only in git
   *  history). `versions`: the row locks old versions of a file that is
   *  harmless now. */
  kind: "path" | "versions";
  /** Which scan found it: the git history, the files as they are now, or a
   *  document's sensitivity label (plan 14 §14.1); or the names-only model
   *  (plan 14 §14.10), or your own model reading documents (§14.11). */
  source: "git-history" | "workspace" | "sensitivity-label" | "model-names" | "model-contents" | "past-sessions";
  /** The level Save gives the file: `no-model` for a key; a label row's is
   *  the level its mapping names. */
  level: string;
  /** A label row: the label as the person's settings name it. */
  label: { name: string; level: string; admin: boolean } | null;
  /** The file the row is about (absolute). For `versions`, the file as it is
   *  now, which does not change. */
  path: string;
  display: string;
  /** The row's name: the file's name, or "2 old versions of config.py". */
  name: string;
  /** For `versions`: the file it sits under. */
  parent: { path: string; display: string; name: string } | null;
  historyOnly: boolean;
  /** "only in git history", or null. */
  tag: string | null;
  /** The rule in plain words (the arbiter's sentence, built from the edit). */
  sentence: string;
  /** The project, `~`-shortened. */
  repo: string;
  /** Where the scan found it, when that is not the git history ("Found in
   *  the file as it is now, on this computer."), else null. */
  note: string | null;
  /** More paths the same key had (renamed or copied), `~`-shortened. */
  more: string[];
  found: FoundVM[];
  /** When it was in the history, one line per version (none for a file
   *  found as it is now: a workspace finding has no commits). */
  when: string[];
  /** What Save changes, in words. */
  impact: string;
  /** The rotation advice, or null. */
  rotate: string | null;
  /** The advice is the softer one (a file found as it is now: nothing shows
   *  the key left the machine). */
  rotateSoft: boolean;
  by: string;
  /** Save can apply it (every edit is one this Mandu knows). */
  applicable: boolean;
  /** Why it cannot be applied, or null. */
  blocked: string | null;
  /** The lines Save adds to policy.yaml. */
  yaml: string;
  /** Old versions the scan found. */
  versions: number;
  createdAt: number;
}

export const SUGGESTED_BY = "Suggested by Mandu's scan";
/** A names-only model's row (plan 14 §14.5): "Suggested by your model <name>". */
export function suggestedByModel(name: string): string {
  return `Suggested by your model ${name}`;
}
/** What a model saw, said on its row: names only, never content. */
export const MODEL_NOTE = "Your model saw only file and folder names, never what the files hold.";
/** What the contents model saw (plan 14 §14.11): the start of this file,
 *  read by a model of your own, never an outside one. */
export const MODEL_CONTENTS_NOTE = "Your own model read the start of this file (at most 16 KB). Nothing of it went to an outside model.";
/** A label row (plan 14 §14.1): what Save writes is Mandu's own rule. */
export const LABEL_NOTE = "If the label is lowered or removed in Office later, this rule stays as it is: change it here if you want it lower.";
export const HISTORY_TAG = "only in git history";
export const ROTATE_WORDS =
  "This key was exposed. Replace it with a new one: a rule keeps the AI from reading it from now on, but cannot undo a push or an earlier session.";
/** macOS: a rule makes the file unreadable but hides no committed version
 *  there (plan 14 §11.3), so the advice to replace the key is stronger. */
export const MACOS_ROTATE_WORDS =
  "This key was exposed. Replace it with a new one: on macOS a rule does not keep the AI from reading its committed versions, and nothing undoes a push or an earlier session.";
/** A file found as it is now (plan 14 §13.4): the arbiter's `rotate` is
 *  false, since nothing shows the key has left the machine. */
export const ROTATE_SOFT_WORDS =
  "If an AI session read this file before, rotate the key: replace it with a new one.";
/** What Save changes for a file found as it is now: discovery hides it from
 *  the next launch (plan 14 §13). */
export const WORKSPACE_IMPACT =
  "Hides this file from the AI from the next time an agent starts.";
export const WORKSPACE_NOTE = "Found in the file as it is now, on this computer.";
/** A file whose key `mandu scan` found in the agents' past sessions (plan 17
 *  §3 item 13): where it comes from. */
export const PAST_SESSIONS_BY = "Suggested by mandu scan";
/** Its note: the key already reached the AI, in a session without this rule. */
export function pastSessionsNote(sessions: number): string {
  return `mandu scan found a key from this file in what your agents sent to the AI in ${sessions === 1 ? "a past session" : `${sessions.toLocaleString("en-US")} past sessions`}. Nothing protects the file yet.`;
}
/** A sensitivity-label row (plan 14 §14.1): where it comes from. */
export const LABEL_BY = "From the document's sensitivity label";
/** What Save changes for a label row: the file gets the level its label is
 *  mapped to, from the next launch. */
export const LABEL_IMPACT =
  "Gives this file the label your settings map its sensitivity label to, from the next time an agent starts.";
/** macOS: said in a history row's impact (a macOS launch hides no
 *  committed version; plan 14 §11.3). */
export const MACOS_HISTORY_WORDS = "On macOS the committed versions stay readable to the AI.";
export const BLOCKED_WORDS =
  "This version of Mandu cannot hide old versions of a file yet, so this cannot be saved. It stays here until Mandu is updated.";

function short(commit: string | null): string | null {
  return commit ? commit.slice(0, 7) : null;
}

/** When one version was in the history. */
export function whenWords(f: Pick<SuggestionFindingWire, "firstCommit" | "lastCommit" | "inHead" | "inIndex">): string {
  const first = short(f.firstCommit);
  const last = short(f.lastCommit);
  const now = f.inHead || f.inIndex;
  if (first === null) return now ? "In the current version (commits not traced)" : "Commits not traced";
  if (last === null || last === first) return now ? `Added in ${first}, still in the current version` : `In ${first}`;
  return now ? `Added in ${first}, last changed in ${last}` : `Added in ${first}, removed in ${last}`;
}

/** "Looks like a private key", "A file named like a credential file". */
function foundWords(d: SuggestionDetectorWire, withLine: boolean): FoundVM {
  const words = d.kind === "catalog-path"
    ? d.words.charAt(0).toUpperCase() + d.words.slice(1)
    : `Looks like ${/^[aeiou]/i.test(d.words) ? "an" : "a"} ${d.words}`;
  return withLine && typeof d.line === "number" && d.line > 0 ? { words, mask: d.mask, line: d.line } : { words, mask: d.mask };
}

function yamlQuote(s: string): string {
  return /^[A-Za-z0-9_./~@+-]+$/.test(s) ? s : JSON.stringify(s);
}

/** The policy.yaml lines an edit adds (paths: / blobs:, plan 14 §8.2). */
export function yamlLines(edits: readonly SuggestionEditWire[]): string {
  const paths = edits.filter((e): e is Extract<SuggestionEditWire, { op: "lock-path" }> => e.op === "lock-path");
  const blobs = edits.filter((e): e is Extract<SuggestionEditWire, { op: "lock-blob" }> => e.op === "lock-blob");
  const out: string[] = [];
  if (paths.length) {
    out.push("paths:");
    for (const e of paths) out.push(`  - path: ${yamlQuote(e.path)}`, `    level: ${e.level}`);
  }
  if (blobs.length) {
    out.push("blobs:");
    for (const e of blobs) {
      out.push(`  - id: ${e.blob}`, `    level: ${e.level}`);
      if (e.note) out.push(`    note: ${JSON.stringify(e.note)}`);
    }
  }
  return out.join("\n");
}

function plural(k: number, one: string, many: string): string {
  return `${k.toLocaleString("en-US")} ${k === 1 ? one : many}`;
}

/** What Save changes, in words. `platform` darwin: a history row hides the
 *  committed versions on Linux only, and says so (MACOS_HISTORY_WORDS); the
 *  file as it is now is made unreadable there. */
function impactWords(s: SuggestionWire, kind: SuggestionRowVM["kind"], platform: NodeJS.Platform = process.platform): string {
  if (s.source === "workspace" || s.source === "past-sessions") return WORKSPACE_IMPACT;
  if (s.source === "sensitivity-label") return LABEL_IMPACT;
  if (s.source === "model-names" || s.source === "model-contents") {
    const m = s.model;
    if (m?.candidate !== "folder") return WORKSPACE_IMPACT;
    const covers = m.covers.length > 0 ? ` Saving it also closes the ${plural(m.covers.length, "suggestion", "suggestions")} it covers.` : "";
    return `Hides this folder and everything in it (${plural(m.files, "file", "files")} the scan listed) from the AI from the next time an agent starts.${covers}`;
  }
  const mac = platform === "darwin";
  const old = s.impact.historicalVersions;
  const hides = (old > 0 ? `Hides ${plural(old, "old version", "old versions")} in git history from the AI` : "Hides it in git history from the AI") + (mac ? " on Linux" : "");
  const here = mac ? ` ${MACOS_HISTORY_WORDS}` : "";
  if (kind === "versions") return `${hides}.${here} The file as it is now does not change.`;
  if (s.historyOnly) return `${hides}.${here} No file you have now changes.`;
  if (!s.impact.workingTreeChanges) return `${hides}.${here}`;
  const files = s.impact.files.length;
  const both = `${hides}, and the file as it is now too${files > 1 ? ` (${plural(files, "file", "files")})` : ""}.`;
  return mac ? `${both} On macOS the AI cannot read the file as it is now, but the committed versions stay readable.` : both;
}

/** The suggestions as the explorer's rows, in the arbiter's order (the ones
 *  only in git history first). `platform` words each impact for the host
 *  the launches run on (default: this process's). */
export function suggestionRows(views: readonly SuggestionWire[], home: string, platform: NodeJS.Platform = process.platform): SuggestionRowVM[] {
  const rows: SuggestionRowVM[] = [];
  for (const s of views) {
    if (s.source === "model-names" || s.source === "model-contents") { rows.push(modelRow(s, home)); continue; }
    const labelRow = s.source === "sensitivity-label";
    // A file whose key reached the AI in a past session (plan 17 §3 item
    // 13): a file row like a workspace one, with the full rotation advice.
    const pastRow = s.source === "past-sessions";
    // A label row is a file found as it is now, like a workspace row.
    const workspace = s.source === "workspace" || labelRow || pastRow;
    const label = labelRow ? s.evidence.label ?? null : null;
    const lockPath = s.edits.find((e) => e.op === "lock-path") as Extract<SuggestionEditWire, { op: "lock-path" }> | undefined;
    const kind: SuggestionRowVM["kind"] = lockPath ? "path" : "versions";
    const rel = s.evidence.paths;
    const abs = (r: string): string => (posix.isAbsolute(r) ? r : posix.join(s.repoRoot, r));
    // The file the row is about: the lock's path; for old versions, the path
    // that exists now (the file they were versions of).
    const current = kind === "versions"
      ? s.evidence.findings.find((f) => f.stillPresent)?.paths[0] ?? rel[0] ?? ""
      : null;
    const path = lockPath ? lockPath.path : abs(current ?? "");
    const display = tildePath(path, home);
    const name = posix.basename(path) || display;
    const versions = kind === "versions"
      ? s.edits.filter((e) => e.op === "lock-blob").length
      : s.impact.historicalVersions;
    const shown = new Set([path]);
    const more = [
      ...s.edits.filter((e) => e.op === "lock-path").map((e) => (e as { path: string }).path),
      ...rel.map(abs),
    ].filter((p) => !shown.has(p) && (shown.add(p), true)).map((p) => tildePath(p, home));
    const seen = new Set<string>();
    const found: FoundVM[] = [];
    for (const f of s.evidence.findings) {
      for (const d of f.detectors) {
        const v = foundWords(d, workspace);
        const k = `${v.words}\u0000${v.mask}\u0000${v.line ?? ""}`;
        if (!seen.has(k)) { seen.add(k); found.push(v); }
      }
    }
    // A label row: the mapping's name for the label, never the file's words.
    if (label) found.push({ words: "Sensitivity label", mask: label.name });
    // A past-sessions row: the key names, never a value.
    if (pastRow) for (const n of (s.evidence.pastSessions?.names ?? []).slice(0, 5)) found.push({ words: "Reached the AI in a past session", mask: n });
    rows.push({
      id: s.id,
      kind,
      source: labelRow ? "sensitivity-label" : pastRow ? "past-sessions" : workspace ? "workspace" : "git-history",
      level: lockPath?.level ?? "no-model",
      label: label ? { name: label.name, level: label.level, admin: typeof label.adminFile === "string" } : null,
      path,
      display,
      name: kind === "versions" ? `${plural(Math.max(versions, 1), "old version", "old versions")} of ${name}` : name,
      parent: kind === "versions" ? { path, display, name } : null,
      historyOnly: !workspace && s.historyOnly,
      tag: !workspace && s.historyOnly ? HISTORY_TAG : null,
      sentence: s.sentence,
      repo: tildePath(s.repoRoot, home),
      note: labelRow ? LABEL_NOTE : pastRow ? pastSessionsNote(s.evidence.pastSessions?.sessions ?? 1) : workspace ? WORKSPACE_NOTE : null,
      more,
      found,
      when: workspace ? [] : s.evidence.findings.map(whenWords),
      impact: impactWords(s, kind, platform),
      // A label is not a key: nothing to rotate.
      rotate: labelRow ? null : pastRow ? ROTATE_WORDS : workspace ? ROTATE_SOFT_WORDS : s.rotate ? (platform === "darwin" ? MACOS_ROTATE_WORDS : ROTATE_WORDS) : null,
      rotateSoft: workspace && !labelRow && !pastRow,
      by: labelRow ? LABEL_BY : pastRow ? PAST_SESSIONS_BY : SUGGESTED_BY,
      applicable: s.applicable,
      blocked: s.applicable ? null : BLOCKED_WORDS,
      yaml: yamlLines(s.edits),
      versions,
      createdAt: s.createdAt,
    });
  }
  return rows;
}

/** A model's suggestion as a row (plan 14 §14.5, §14.11): a row on the
 *  file or folder it locks, "Suggested by your model <name>", the reason in
 *  the arbiter's words, what the model saw, what Save hides and at what
 *  level (a contents answer may be below hidden from the AI). No commits, no
 *  mask, no rotation advice (no key was found). */
function modelRow(s: SuggestionWire, home: string): SuggestionRowVM {
  const lock = s.edits.find((e) => e.op === "lock-path") as Extract<SuggestionEditWire, { op: "lock-path" }> | undefined;
  const path = lock ? lock.path.replace(/\\([*?[\]\\])/g, "$1") : posix.join(s.repoRoot, s.evidence.paths[0] ?? "");
  const display = tildePath(path, home);
  const m = s.model;
  const words = m?.reasonWords ?? "looks sensitive";
  const contents = s.source === "model-contents";
  return {
    id: s.id,
    kind: "path",
    source: contents ? "model-contents" : "model-names",
    level: lock?.level ?? "no-model",
    label: null,
    path,
    display,
    name: posix.basename(path) || display,
    parent: null,
    historyOnly: false,
    tag: null,
    sentence: s.sentence,
    repo: tildePath(s.repoRoot, home),
    note: contents ? MODEL_CONTENTS_NOTE : MODEL_NOTE,
    more: [],
    found: [{ words: words.charAt(0).toUpperCase() + words.slice(1), mask: contents ? "from what the file says" : m?.candidate === "folder" ? "from the folder's file names" : "from the file's name" }],
    when: [],
    impact: impactWords(s, "path"),
    rotate: null,
    rotateSoft: false,
    by: suggestedByModel(m?.endpoint ?? "?"),
    applicable: s.applicable,
    blocked: s.applicable ? null : BLOCKED_WORDS,
    yaml: yamlLines(s.edits),
    versions: 0,
    createdAt: s.createdAt,
  };
}

// ── a scan, in one line ─────────────────────────────────────────────────────

/** A size in the page's words ("256 KB", "64 MB"). */
function sizeWords(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${Math.round(bytes / (1024 * 1024))} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function listWords(items: string[]): string {
  return items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}

/** Why a folder was not walked, in plain words; null for a folder another
 *  one already covers (walked as part of it, so nothing to say). */
function rootReasonWords(reason: string): string | null {
  if (/^(inside another root|the same as another root)$/.test(reason)) return null;
  if (/^Mandu's own state/.test(reason)) return "Mandu's own files";
  if (/credentials/.test(reason)) return "the AI agent's own sign-in files";
  if (/pseudo-filesystem/.test(reason)) return "a system folder";
  if (reason === "not a directory") return "not a folder";
  return reason.replace(/, not scanned$/, "");
}

/** Where the workspace scan read: "~/proj", "~/proj and your home folder",
 *  "3 folders". */
function workspaceWhere(w: WorkspaceScanWire, home: string): string {
  const names = w.roots
    .filter((x) => x.reason === undefined)
    .map((x) => (x.tier === "home" && x.root === home ? "your home folder" : tildePath(x.root, home)));
  return names.length <= 2 ? listWords(names) : plural(names.length, "folder", "folders");
}

/** What the workspace scan's caps left unchecked, in plain words (the
 *  arbiter's own `capped.lines` name settings, not for this page). */
export function workspaceCappedWords(w: WorkspaceScanWire): string | null {
  const c = w.capped;
  const items: string[] = [];
  if (c.tooBig > 0) items.push(`${plural(c.tooBig, "file", "files")} over ${sizeWords(w.limits.fileMaxBytes)}`);
  if (c.overTotal > 0) items.push(`${plural(c.overTotal, "file", "files")} past the ${sizeWords(w.limits.totalMaxBytes)} it reads in all`);
  if (c.overFiles > 0) items.push(`${plural(c.overFiles, "file", "files")} past the ${w.limits.maxFiles.toLocaleString("en-US")} it looks at`);
  if (c.overTime > 0) items.push(`${plural(c.overTime, "file or folder", "files or folders")} left when its ${Math.round(w.limits.timeoutMs / 1000)} seconds ran out`);
  if (c.unreadable > 0) items.push(`${plural(c.unreadable, "file or folder", "files or folders")} it could not open`);
  if (c.depth > 0) items.push(`${plural(c.depth, "folder", "folders")} nested too deep`);
  const gaps = items.length;
  if (c.binary > 0) items.push(plural(c.binary, "binary file", "binary files"));
  if (c.symlinks > 0) items.push(plural(c.symlinks, "link to a file", "links to files"));
  if ((c.special ?? 0) > 0) items.push(plural(c.special!, "special file", "special files"));
  // A second checkout of a project (plan 14 §13.9): its files are the
  // project's again, so this is not a gap.
  if ((c.worktrees ?? 0) > 0) items.push(plural(c.worktrees!, "extra copy of a git project", "extra copies of a git project"));
  if (items.length === 0) return null;
  return `Not checked: ${listWords(items)}.${gaps > 0 ? " There may be more keys in those." : ""}`;
}

/** A part of the line under Scan (dashboard.md §4.25r): text, or the one
 *  place it names, Settings › Sensitivity labels (`labels`). It names the
 *  place, never an address: the page builds the link (home.js `placeLink`),
 *  as for the Home hero's. */
export type ScanSummaryPart = HomeTextPart | { kind: "link"; text: string; to: "labels" };

const joinedParts = (parts: readonly ScanSummaryPart[]): string => parts.map((p) => p.text).join("");

/** Sentences, each a string or parts, as one run of parts with a space
 *  between sentences; neighbouring text merges into one part. */
function sentenceParts(items: ReadonlyArray<string | readonly ScanSummaryPart[]>): ScanSummaryPart[] {
  const out: ScanSummaryPart[] = [];
  const push = (p: ScanSummaryPart): void => {
    const last = out.at(-1);
    if (p.kind === "text" && last?.kind === "text") out[out.length - 1] = { kind: "text", text: last.text + p.text };
    else out.push({ ...p });
  };
  items.forEach((item, i) => {
    if (i > 0) push({ kind: "text", text: " " });
    for (const p of typeof item === "string" ? [{ kind: "text" as const, text: item }] : item) push(p);
  });
  return out;
}

/** What a finished scan found, for the line under Scan: `scanSummaryParts`
 *  joined. */
export function scanSummary(r: SuggestPolicyWire, home: string): string {
  return joinedParts(scanSummaryParts(r, home));
}

/** What a finished scan found, for the line under Scan, as parts. It names
 *  both scans (plan 14 §13.6): the git history it read, and the files it
 *  checked (the documents whose sensitivity labels it read among them),
 *  then what waits and what a cap left unread. The label sentence links
 *  where a level is set. */
export function scanSummaryParts(r: SuggestPolicyWire, home: string): ScanSummaryPart[] {
  if (!r.axis) return sentenceParts(['Protection is off, so nothing was scanned. Turn it on in Settings to scan.']);
  const repos = r.scan?.repos ?? [];
  const found = repos.filter((x) => x.repoRoot !== null);
  const noHistory = r.scan !== null && repos.length > 0 && found.length === 0
    ? `No git history was found in ${repos.map((x) => tildePath(x.root, home)).join(", ")}.`
    : null;
  const w = r.workspaceScan ?? null;
  if (noHistory !== null && w === null) return sentenceParts([noHistory]);
  const history = r.scan !== null && noHistory === null
    ? (found.length === 1 ? tildePath(found[0]!.repoRoot!, home) : plural(found.length, "project", "projects"))
    : null;
  // An Office file is never read as text: the label read opens it under its
  // own budgets and counts it apart (secret-workspace-scan.ts, S4), a
  // document the rules cover too. Until 2026-10-08 the counts left those
  // out, so a folder of labelled documents read "Scanned 0 files" beside
  // "1 file carries a sensitivity label".
  const lab = w?.labels ?? null;
  const labRan = lab !== null && lab.mode !== "off";
  const files = w ? w.counts.read + w.counts.cached + (labRan ? lab.read + lab.cached : 0) : 0;
  const coveredFiles = w ? w.counts.covered + (labRan ? lab.covered : 0) : 0;
  const wWhere = w ? workspaceWhere(w, home) : "";
  let head: string;
  if (history !== null && w !== null) {
    head = `Scanned the git history of ${history} and ${plural(files, "file", "files")}${wWhere && wWhere !== history ? ` in ${wWhere}` : ""}.`;
  } else if (history !== null) {
    head = `Scanned the git history of ${history}.`;
  } else if (w !== null) {
    head = wWhere ? `Scanned ${plural(files, "file", "files")} in ${wWhere}.` : "No folder could be scanned.";
  } else {
    head = "Scanned.";
  }
  const waiting = r.suggestions.length;
  const parts: Array<string | readonly ScanSummaryPart[]> = [
    head,
    waiting === 0
      ? "Nothing new to review."
      : `${plural(waiting, "possible key", "possible keys")} to review${r.counts.filed > 0 && r.counts.filed < waiting ? ` (${r.counts.filed} new)` : ""}.`,
  ];
  if (noHistory !== null) parts.push(noHistory);
  if (r.counts.covered > 0) parts.push(`${plural(r.counts.covered, "key is", "keys are")} already protected.`);
  if (coveredFiles > 0) parts.push(`${plural(coveredFiles, "file", "files")} your rules already protect ${coveredFiles === 1 ? "was" : "were"} not opened.`);
  if (r.counts.dismissed > 0) parts.push(`${plural(r.counts.dismissed, "finding", "findings")} you marked as not a secret ${r.counts.dismissed === 1 ? "was" : "were"} left out.`);
  if (r.counts.overCap > 0) parts.push(`${r.counts.overCap} more wait until you review these.`);
  const c = r.scan?.capped;
  if (c && (c.unlisted || c.tooBig + c.overTotal + c.overTime > 0)) parts.push("Part of the history was too large to read in time, so there may be more.");
  // Not a cap: git failed to hand some of it over (secret-discovery.md §3.2).
  if (c && (c.readFailed ?? 0) > 0) parts.push("Part of the history could not be read, so there may be more.");
  if (w) {
    const skipped = w.roots
      .map((x) => (x.reason === undefined ? null : [x, rootReasonWords(x.reason)] as const))
      .filter((x): x is readonly [WorkspaceScanWire["roots"][number], string] => x !== null && x[1] !== null)
      .map(([x, why]) => `${tildePath(x.root, home)} (${why})`);
    if (skipped.length) parts.push(`Not scanned: ${skipped.join(", ")}.`);
    const capped = workspaceCappedWords(w);
    if (capped) parts.push(capped);
    const labels = labelScanParts(lab);
    if (labels) parts.push(labels);
  }
  return sentenceParts(parts);
}

/** What the label read found, in plain words: `labelScanParts` joined, or
 *  null. */
export function labelScanWords(l: LabelScanWire | null): string | null {
  const parts = labelScanParts(l);
  return parts === null ? null : joinedParts(parts);
}

/** The fields of a label read that say what it could not tell: the scan
 *  answer's, or the one Settings › Sensitivity labels keeps (each optional
 *  there: an older scan's answer has none of them). */
export type LabelUncheckedWire = Partial<Pick<LabelScanWire, "encrypted" | "unreadable" | "capped" | "limits">>;

/** The documents the label read never checked, in plain words, or null: its
 *  own caps (`capped`, under its own `limits`, apart from the text read's)
 *  and the documents it could not read. The arbiter's `capped.lines` name
 *  them for the terminal; until 2026-10-08 the page left them out. */
export function labelGapWords(l: LabelUncheckedWire): string | null {
  const max = l.limits?.maxFiles;
  const total = l.limits?.totalMaxBytes;
  const items: string[] = [];
  const overFiles = l.capped?.overFiles ?? 0;
  const overBytes = l.capped?.overBytes ?? 0;
  const unreadable = l.unreadable ?? 0;
  // No limits (an older answer): the cap without its number.
  if (overFiles > 0) items.push(`${plural(overFiles, "document", "documents")} ${max !== undefined ? `past the ${max.toLocaleString("en-US")} it looks at` : "past its file limit"}`);
  if (overBytes > 0) items.push(`${plural(overBytes, "document", "documents")} ${total !== undefined ? `past the ${sizeWords(total)} it reads in all` : "past its size limit"}`);
  if (unreadable > 0) items.push(`${plural(unreadable, "document", "documents")} it could not read`);
  return items.length ? `Not checked for a sensitivity label: ${listWords(items)}.` : null;
}

/** The encrypted documents the label read could not open, in plain words,
 *  or null. */
export function labelEncryptedWords(l: LabelUncheckedWire): string | null {
  const n = l.encrypted ?? 0;
  return n > 0 ? `${plural(n, "encrypted document was", "encrypted documents were")} not read, so ${n === 1 ? "its" : "their"} sensitivity label is not known.` : null;
}

/** What a label read could not tell, as the sentences the scan line ends
 *  with: the encrypted documents (`labelEncryptedWords`), then the documents
 *  it left unchecked (`labelGapWords`). Settings › Sensitivity labels ends
 *  its note with the same sentences (sensitivity-labels.ts). */
export function labelUncheckedSentences(l: LabelUncheckedWire): string[] {
  return [labelEncryptedWords(l), labelGapWords(l)].filter((x): x is string => x !== null);
}

/** What the label read found (plan 14 §14.1): the labels no setting maps
 *  yet (the terminal's "12 files carry a sensitivity label you have not
 *  mapped"), then what it could not tell (`labelUncheckedSentences`: the
 *  encrypted documents and the ones it left unchecked). Settings › Sensitivity labels,
 *  where a level is set, is a link part (until 2026-10-08, plain text).
 *  Null when there is nothing to say. */
export function labelScanParts(l: LabelScanWire | null): ScanSummaryPart[] | null {
  if (!l || l.mode === "off") return null;
  const parts: Array<string | readonly ScanSummaryPart[]> = [];
  if (l.unmappedFiles > 0) {
    parts.push([
      { kind: "text", text: `${plural(l.unmappedFiles, "file carries", "files carry")} a sensitivity label you have not chosen a level for: set it in ` },
      { kind: "link", text: "Settings › Sensitivity labels", to: "labels" },
      { kind: "text", text: "." },
    ]);
  }
  parts.push(...labelUncheckedSentences(l));
  return parts.length ? sentenceParts(parts) : null;
}
