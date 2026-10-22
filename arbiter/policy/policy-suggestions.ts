/**
 * policy-suggestions — the generator of confidentiality plan 14 §4: turn the
 * git-history scan's findings (secret-history-scan.ts) into the typed
 * `PolicyEdit`s that would cover them, for a human to review. Mandu-new (no
 * reference origin).
 *
 * `suggestEdits(findings, law, opts)` is PURE over its seams (`exists`, the
 * clock): one suggestion per secret (the findings of one repository that
 * share a path are one secret: the versions of one file), each with
 *
 *   - its edits, only `lock-path` and `lock-blob` at `no-model` (§4 table):
 *       a path gone from the work tree          → lock-path (the deleted key)
 *       a present path whose current content
 *         holds the key (the blob is in HEAD or
 *         the index)                             → lock-path
 *       a present path whose current content
 *         does not (a key once inline, removed)  → lock-blob (the old versions)
 *       covered (the file is protected now, or
 *         the law already labels the path/blob)  → none; listed as covered
 *   - a plain sentence built from the EDITS (the Rules page's words,
 *     dashboard/src/view-model/policy-proposals.ts `editRow`), never from a
 *     finding's text;
 *   - its evidence (paths, blobs, commits, each detector's kind, rule and
 *     fixed mask: the scan's masks, which never carry a value);
 *   - its impact (old versions found, whether the working tree changes);
 *   - the rotation advice (the key was exposed; a lock cannot undo that).
 *
 * THE TIGHTENING CHECK (§4): every edit list runs through `evaluateEdits`
 * (applyEdits + validate + `policyDelta`) against the law in force; a
 * suggestion whose edits are invalid or relax anything is DROPPED, and an
 * edit with no effect on the law (it already says this) is removed. A
 * suggestion left with no edit is covered.
 *
 * `lock-blob` (§8.2) is in the law's grammar since 2026-09-30, so the check
 * evaluates it like `lock-path` (a new blob lock above `public` is a
 * tightening, `blob-lock` facet). An edit whose op a build does not know
 * (a row filed by a newer arbiter, read by an older one) is still kept as
 * built and refused at APPLY time as `unsupported`.
 *
 * `suggestWorkspaceEdits` (plan 14 §13.4) is the same generator for the
 * workspace scan (secret-workspace-scan.ts): one `lock-path` per file,
 * source `workspace`, key `workspace:path:<literal path>`, the evidence in
 * the history shape without commits, and `rotate: false` (nothing shows the
 * key left the machine). Filing across the two sources (one suggestion per
 * file) is policy-suggestion-ops.ts's.
 *
 * `suggestLabelEdits` (plan 14 §14.1, §14.9) is the generator for S4: a
 * labelled Office file whose strictest mapped label is above `public`
 * becomes `lock-path { path, level }`, source `sensitivity-label`, key
 * `sensitivity-label:<literal path>`, the sentence naming the MAPPING's
 * name. A `no-model` lock meets the tightening check; a lower one meets
 * `judgeHumanLabelLock` and is filed `humanOnly` (a person applies it on
 * the admin channel).
 */
import { isAbsolute, join, relative } from "node:path";
import type { CompiledPolicy } from "./compiled-policy.js";
import type { PolicyFileConfig } from "./load-policy.js";
import { resolvePathLabel } from "./path-labels.js";
import { POLICY_EDIT_OPS, evaluateEdits, pathIdentity, type PolicyEdit } from "./policy-edit.js";
import type { SecretHistoryDetector, SecretHistoryFinding } from "./secret-history-scan.js";
import type { SecretWorkspaceFinding } from "./secret-workspace-scan.js";
import { strictestMapping, type LabelMappingEntry, type SensitivityLabelFinding } from "./sensitivity-labels.js";
import type { ModelSuggestionFacts } from "./policy-model.js";
import type { InboundSpecId } from "./tool-inbound.js";
import { createHash } from "node:crypto";

// ── types ────────────────────────────────────────────────────────────────────

/** The grammar's `lock-blob` (plan 14 §8.2): the git object with this id
 *  (`sha1:<40 hex>` or `sha256:<64 hex>`) is labelled at `level` in every
 *  repository. A suggestion only ever builds it at `no-model`. */
export type LockBlobEdit = Extract<PolicyEdit, { op: "lock-blob" }> & { level: "no-model" };

export type LockPathEdit = Extract<PolicyEdit, { op: "lock-path" }>;

/** What a suggestion may carry: a no-model lock on a path or on a blob. */
export type SuggestionEdit = LockPathEdit | LockBlobEdit;

/** One detector as the review shows it: never a value. */
export interface SuggestionDetectorView {
  kind: "content-shape" | "catalog-path";
  /** The shape (`private-key`, …) or the deciding catalog/label rule. */
  rule: string;
  /** The scan's fixed mask (`ghp_…`, a key block's header, `DB_PASSWORD=…`),
   *  or for a catalog hit the path it was found at. */
  mask: string;
  /** The detector in plain words. */
  words: string;
  line?: number;
  path?: string;
}

/** One secret-shaped blob behind a suggestion (a finding, masked). */
export interface SuggestionFindingView {
  blob: string;
  /** Repo-relative paths the blob had. */
  paths: string[];
  firstCommit: string | null;
  lastCommit: string | null;
  inHead: boolean;
  inIndex: boolean;
  stillPresent: boolean;
  detectors: SuggestionDetectorView[];
}

export interface SuggestionEvidence {
  /** Every repo-relative path of the secret's findings, sorted. */
  paths: string[];
  /** Every blob, sorted. */
  blobs: string[];
  findings: SuggestionFindingView[];
  /** No path of the secret exists in the work tree now. */
  historyOnly: boolean;
  /** Source `sensitivity-label` only: the label that decided it (then
   *  `findings` is empty). */
  label?: SuggestionLabelEvidence;
  /** Source `past-sessions` only (plan 17 §3 item 13): what `mandu scan`
   *  found of the file's keys in the agents' past sessions (then `findings`
   *  is empty): the key names the arbiter itself read in the file, and the
   *  scan's session count and last date. Names and counts, never a value. */
  pastSessions?: SuggestionPastSessionsEvidence;
}

/** A `past-sessions` suggestion's evidence (plan 17 §3 item 13). */
export interface SuggestionPastSessionsEvidence {
  /** The key names in the file (`STRIPE_KEY`, `hosts.github.com.token`). */
  names: string[];
  /** Past sessions in which one of them reached the AI (the scan's count). */
  sessions: number;
  /** The last one (ISO), when the scan said. */
  last: string | null;
}

export interface SuggestionImpact {
  /** Old versions the scan found (blobs in neither HEAD nor the index). A
   *  path lock hides every version of the path, so this is a floor. */
  historicalVersions: number;
  /** A lock falls on a file that exists now: it disappears from the AI's view. */
  workingTreeChanges: boolean;
  /** Those files, repo-relative. */
  files: string[];
}

/** The scans a suggestion can come from; `model-names` is the optional
 *  names-only model (plan 14 §14.4, T1), `model-contents` the declared
 *  local model reading documents (§14.4, T2, §14.11), `past-sessions` a
 *  file whose key `mandu scan` found in the agents' past sessions (plan 17
 *  §3 item 13). */
export type SuggestionSource = "git-history" | "workspace" | "sensitivity-label" | "model-names" | "model-contents" | "past-sessions";

/** A sensitivity-label suggestion's evidence (plan 14 §14.1): the label and
 *  the MAPPING's words for it, never the file's. */
export interface SuggestionLabelEvidence {
  /** The label's GUID and its tenant's (null: the file names none). */
  id: string;
  site: string | null;
  /** The mapping's `name` (the person's or the administrator's words). */
  name: string;
  /** The mapped level. */
  level: string;
  /** Set when the administrator's layer maps it (its file). */
  adminFile?: string;
}

/** The generator's answer for one secret. No field carries a value. */
export interface Suggestion {
  /** Dedup identity (plan 14 §5.1): the source and what the edits lock. */
  findingKey: string;
  /** Which scan found it: S1 (git history) or S2 (the files on disk, plan 14
   *  §13). Renderers branch on it: a workspace suggestion has no commits,
   *  and its rotation line is softer (`rotate: false`). */
  source: SuggestionSource;
  repoRoot: string;
  edits: SuggestionEdit[];
  /** The rule in plain words, from the edits. */
  sentence: string;
  evidence: SuggestionEvidence;
  impact: SuggestionImpact;
  historyOnly: boolean;
  /** The key was exposed: rotate it. True for a history finding (it was
   *  committed); false for a workspace one, since nothing shows it left the
   *  machine (renderers say "If an AI session read this file before, rotate
   *  the key"). */
  rotate: boolean;
  /** Only a person may apply it, on the admin channel (the dashboard): a
   *  sensitivity-label suggestion below `no-model`, whose new lock the delta
   *  cannot prove tighter (a lock below no-model overrides the secret catalog
   *  under it, policy-delta.ts). Absent: false. */
  humanOnly?: boolean;
  /** A `model-names` suggestion (plan 14 §14.4): the destination model's
   *  name and what it answered, as enums and the arbiter's own words. Never
   *  a string the model wrote. */
  model?: ModelSuggestionFacts;
}

/** A secret the law already covers: listed, not suggested. */
export interface CoveredSecret {
  repoRoot: string;
  paths: string[];
  blobs: string[];
  /** `protected-now`: the file is protected now (catalog or label), so its
   *  object twins hide every version; `law`: the law already locks every
   *  path/blob the suggestion would. */
  why: "protected-now" | "law";
}

/** A suggestion the tightening check threw out. */
export interface DroppedSuggestion {
  findingKey: string;
  repoRoot: string;
  why: "invalid" | "relaxes";
  problems: string[];
}

export interface SuggestEditsResult {
  suggestions: Suggestion[];
  covered: CoveredSecret[];
  dropped: DroppedSuggestion[];
}

/** The law the edits are judged against: a compiled law, or its parts. */
export type SuggestLaw = Pick<CompiledPolicy, "specId" | "document" | "pathLabels">;

export interface SuggestEditsOptions {
  /** Does this absolute path exist now? */
  exists: (absPath: string) => boolean;
  /** The user's HOME, for `~` in labels and the sentence. */
  home?: string;
  now?: number;
}

// ── words (the Rules page's terms, dashboard.md §4.25d) ──────────────────────

/** The content detector's shapes in plain words (doctor-secrets.ts). */
export const SHAPE_WORDS: Readonly<Record<string, string>> = {
  "private-key": "private key",
  "aws-access-key-id": "AWS access key",
  "aws-secret-key": "AWS secret key",
  "github-token": "GitHub token",
  "gitlab-token": "GitLab token",
  "anthropic-key": "Anthropic API key",
  "openai-key": "OpenAI-style API key",
  "slack-token": "Slack token",
  "stripe-key": "Stripe live key",
  "google-api-key": "Google API key",
  "npm-token": "npm token",
  "pypi-token": "PyPI token",
  "huggingface-token": "Hugging Face token",
  "url-password": "password in a web address",
  "credential-assignment": "password or token written in the file",
};

export const CATALOG_PATH_WORDS = "a file named like a credential file";

function detectorView(d: SecretHistoryDetector): SuggestionDetectorView {
  if (d.kind === "content-shape") {
    return { kind: d.kind, rule: d.rule, mask: d.preview, words: SHAPE_WORDS[d.rule] ?? "credential", line: d.line };
  }
  return { kind: d.kind, rule: d.rule, mask: d.path, words: CATALOG_PATH_WORDS, path: d.path };
}

/** A path as the sentence shows it: `~/…` under HOME, else as written. */
export function displayPath(abs: string, home?: string): string {
  if (home && (abs === home || abs.startsWith(home.endsWith("/") ? home : home + "/"))) {
    return abs === home ? "~" : "~/" + abs.slice(home.length).replace(/^\/+/, "");
  }
  return abs;
}

/** A literal path as a `paths:` entry: glob metacharacters escaped, so a
 *  committed file named `a[1].env` is a literal lock, not a pattern. */
export function literalLabelPath(abs: string): string {
  return abs.replace(/[*?[\]\\]/g, "\\$&");
}

/** `sha1:<hex>` / `sha256:<hex>` for a git object name, or null. */
export function blobId(oid: string): string | null {
  const o = oid.toLowerCase();
  if (/^[0-9a-f]{40}$/.test(o)) return `sha1:${o}`;
  if (/^[0-9a-f]{64}$/.test(o)) return `sha256:${o}`;
  return null;
}

const short = (c: string | null): string => (c === null ? "?" : c.slice(0, 7));

/** The rule in plain words, from the edits (one clause per edit, with the
 *  lock-blobs of one file counted in one clause). `gone` names the locked
 *  paths that exist only in history; `blobPath` names the file each blob
 *  lock hides old versions of. */
export function suggestionSentence(
  edits: readonly SuggestionEdit[],
  ctx: { home?: string; gone?: ReadonlySet<string>; blobPath?: ReadonlyMap<string, string> } = {},
): string {
  const clauses: string[] = [];
  const blobsByFile = new Map<string, number>();
  for (const e of edits) {
    if (e.op === "lock-path") {
      const shown = displayPath(e.path.replace(/\\([*?[\]\\])/g, "$1"), ctx.home);
      clauses.push(`Make ${shown} a secret no AI may read${ctx.gone?.has(e.path) ? " (only in git history)" : ""}`);
    } else {
      const file = ctx.blobPath?.get(e.blob) ?? "a file";
      blobsByFile.set(file, (blobsByFile.get(file) ?? 0) + 1);
    }
  }
  for (const [file, n] of blobsByFile) {
    clauses.push(`Hide ${n === 1 ? "an old version" : `${n} old versions`} of ${file === "a file" ? file : displayPath(file, ctx.home)} from the AI`);
  }
  return clauses.join("; ");
}

// ── the generator ────────────────────────────────────────────────────────────

/** The dedup key of a suggestion's edits: the source and what they lock. */
export function findingKeyOf(edits: readonly SuggestionEdit[]): string {
  const ids = edits.map((e) => (e.op === "lock-path" ? `path:${e.path}` : `blob:${e.blob}`)).sort();
  const key = `git-history:${ids.join("|")}`;
  return key.length <= 512 ? key : `git-history:sha256:${createHash("sha256").update(ids.join("\n")).digest("hex")}`;
}

/** The findings of one repository that share a path: one secret. Stable
 *  order (the scan's). */
export function groupFindings(findings: readonly SecretHistoryFinding[]): SecretHistoryFinding[][] {
  const parent = findings.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
  const owner = new Map<string, number>();
  findings.forEach((f, i) => {
    for (const p of f.paths) {
      const k = `${f.repoRoot}\0${p}`;
      const j = owner.get(k);
      if (j === undefined) owner.set(k, i);
      else parent[find(i)] = find(j);
    }
  });
  const groups = new Map<number, SecretHistoryFinding[]>();
  findings.forEach((f, i) => {
    const r = find(i);
    const g = groups.get(r) ?? [];
    g.push(f);
    groups.set(r, g);
  });
  return [...groups.values()];
}

function isKnownOp(op: string): boolean {
  return (POLICY_EDIT_OPS as readonly string[]).includes(op);
}

type Judge = { verdict: "ok"; edits: SuggestionEdit[] } | { verdict: "covered" } | { verdict: "invalid" | "relaxes"; problems: string[] };

/** The tightening check (§4): drop edits that change nothing, then judge
 *  the list. Edits this build's grammar does not know are kept as built. */
export function judgeEdits(
  law: { specId: InboundSpecId; document: PolicyFileConfig | null },
  edits: readonly SuggestionEdit[],
  now?: number,
): Judge {
  const opts = now !== undefined ? { now } : {};
  const known = edits.filter((e) => isKnownOp(e.op));
  const unknown = edits.filter((e) => !isKnownOp(e.op));
  const effective: SuggestionEdit[] = [];
  for (const e of known) {
    const one = evaluateEdits(law, [e], opts);
    if (!one.ok) return { verdict: "invalid", problems: one.problems };
    if (one.delta.relaxations.length > 0) return { verdict: "relaxes", problems: one.delta.relaxations.map((r) => r.detail) };
    if (one.delta.tightenings.length > 0) effective.push(e);
  }
  if (effective.length > 0) {
    const all = evaluateEdits(law, effective, opts);
    if (!all.ok) return { verdict: "invalid", problems: all.problems };
    if (all.delta.relaxations.length > 0) return { verdict: "relaxes", problems: all.delta.relaxations.map((r) => r.detail) };
  }
  const kept = [...effective, ...unknown];
  // Keep the generator's order (paths, then blobs).
  kept.sort((a, b) => edits.indexOf(a) - edits.indexOf(b));
  return kept.length === 0 ? { verdict: "covered" } : { verdict: "ok", edits: kept };
}

/** Does the law already label this blob above public (the `blobs:` section
 *  of §8.2, when the document has one)? */
function lawLocksBlob(doc: PolicyFileConfig | null, id: string): boolean {
  const blobs = (doc as { blobs?: unknown } | null)?.blobs;
  if (!Array.isArray(blobs)) return false;
  return blobs.some((b) => b !== null && typeof b === "object" && (b as { id?: unknown }).id === id && (b as { level?: unknown }).level !== "public");
}

/** Does the law already cover this edit's subject (the path resolves to a
 *  label above public, or the blob is locked above public)? A covered path
 *  is the person's call (even at `any-model`): a scan does not raise it. */
export function editCovered(e: SuggestionEdit, law: SuggestLaw, home?: string): boolean {
  if (e.op === "lock-blob") return lawLocksBlob(law.document, e.blob);
  const d = resolvePathLabel(e.path.replace(/\\([*?[\]\\])/g, "$1"), law.pathLabels, home);
  return d !== null && d.level !== "public";
}

/** Plan 14 §4: findings → suggestions. Pure over `opts.exists`. */
export function suggestEdits(findings: readonly SecretHistoryFinding[], law: SuggestLaw, opts: SuggestEditsOptions): SuggestEditsResult {
  const out: SuggestEditsResult = { suggestions: [], covered: [], dropped: [] };
  const labelled = (abs: string): boolean => {
    const d = resolvePathLabel(abs, law.pathLabels, opts.home);
    return d !== null && d.level !== "public";
  };
  for (const group of groupFindings(findings)) {
    const repoRoot = group[0]!.repoRoot;
    const abs = (rel: string): string => (isAbsolute(rel) ? rel : join(repoRoot, rel));
    const allPaths = [...new Set(group.flatMap((f) => f.paths))].sort();
    const allBlobs = [...new Set(group.map((f) => f.blob))].sort();
    const open = group.filter((f) => !f.pathStillSecretByCatalog);
    if (open.length === 0) {
      out.covered.push({ repoRoot, paths: allPaths, blobs: allBlobs, why: "protected-now" });
      continue;
    }
    const present = new Map<string, boolean>();
    const isPresent = (rel: string): boolean => {
      let v = present.get(rel);
      if (v === undefined) present.set(rel, (v = opts.exists(abs(rel))));
      return v;
    };
    const lockPaths = new Map<string, LockPathEdit>();
    const gone = new Set<string>();
    const blobLocks = new Map<string, LockBlobEdit>();
    const blobPath = new Map<string, string>();
    const files = new Set<string>();
    for (const f of open) {
      const current = f.inHead || f.inIndex;
      let blobAt: string | null = null;
      for (const rel of f.paths) {
        const a = abs(rel);
        if (!isPresent(rel)) {
          if (labelled(a)) continue;
          const path = literalLabelPath(a);
          lockPaths.set(path, { op: "lock-path", path, level: "no-model" });
          gone.add(path);
        } else if (current) {
          if (labelled(a)) continue;
          const path = literalLabelPath(a);
          lockPaths.set(path, { op: "lock-path", path, level: "no-model" });
          files.add(rel);
        } else {
          blobAt ??= rel;
        }
      }
      if (blobAt !== null) {
        const id = blobId(f.blob);
        if (id !== null && !lawLocksBlob(law.document, id)) {
          blobLocks.set(id, {
            op: "lock-blob", blob: id, level: "no-model",
            note: `found in git history: ${blobAt} (${short(f.firstCommit)}..${short(f.lastCommit)})`,
          });
          blobPath.set(id, abs(blobAt));
        }
      }
    }
    const built: SuggestionEdit[] = [...lockPaths.values(), ...blobLocks.values()];
    const judged = built.length === 0 ? ({ verdict: "covered" } as const) : judgeEdits(law, built, opts.now);
    if (judged.verdict === "covered") {
      out.covered.push({ repoRoot, paths: allPaths, blobs: allBlobs, why: "law" });
      continue;
    }
    if (judged.verdict !== "ok") {
      out.dropped.push({ findingKey: findingKeyOf(built), repoRoot, why: judged.verdict, problems: judged.problems });
      continue;
    }
    const edits = judged.edits;
    const historyOnly = allPaths.every((p) => !isPresent(p));
    const lockedFiles = [...files].filter((rel) => edits.some((e) => e.op === "lock-path" && e.path === literalLabelPath(abs(rel)))).sort();
    out.suggestions.push({
      findingKey: findingKeyOf(edits),
      source: "git-history",
      repoRoot,
      edits,
      sentence: suggestionSentence(edits, { home: opts.home, gone, blobPath }),
      evidence: {
        paths: allPaths,
        blobs: allBlobs,
        findings: group.map((f) => ({
          blob: f.blob, paths: [...f.paths], firstCommit: f.firstCommit, lastCommit: f.lastCommit,
          inHead: f.inHead, inIndex: f.inIndex, stillPresent: f.stillPresent,
          detectors: f.detectors.map(detectorView),
        })),
        historyOnly,
      },
      impact: {
        historicalVersions: group.filter((f) => !f.inHead && !f.inIndex).length,
        workingTreeChanges: lockedFiles.length > 0,
        files: lockedFiles,
      },
      historyOnly,
      rotate: true,
    });
  }
  // History-only secrets first (nothing hides them today), then by path.
  out.suggestions.sort((a, b) => Number(b.historyOnly) - Number(a.historyOnly) || a.findingKey.localeCompare(b.findingKey));
  return out;
}

// ── the workspace generator (plan 14 §13.4) ──────────────────────────────────

/** The dedup key of a workspace suggestion: `workspace:path:<literal path>`
 *  (a hash past 512 characters, as for history). */
export function workspaceFindingKey(literalPath: string): string {
  const key = `workspace:path:${literalPath}`;
  return key.length <= 512 ? key : `workspace:sha256:${createHash("sha256").update(`path:${literalPath}`).digest("hex")}`;
}

/**
 * Plan 14 §13.4: workspace findings (secret-workspace-scan.ts) → one
 * `lock-path { path, level: "no-model" }` suggestion per file, through the
 * same tightening check (`judgeEdits`). Pure. The evidence keeps the history
 * shape so one wire type serves both sources: one path (relative to the
 * suggestion's `repoRoot`: the finding's work tree, else its scan root) and
 * one finding entry with `blob: ""`, no commits, not in HEAD or the index,
 * present. The impact: no historical versions, the working tree changes
 * (that file). `rotate` is false: nothing shows the key left the machine.
 */
export function suggestWorkspaceEdits(
  findings: readonly SecretWorkspaceFinding[],
  law: SuggestLaw,
  opts: { home?: string; now?: number } = {},
): SuggestEditsResult {
  const out: SuggestEditsResult = { suggestions: [], covered: [], dropped: [] };
  const done = new Set<string>();
  for (const f of findings) {
    if (done.has(f.path) || !isAbsolute(f.path)) continue;
    done.add(f.path);
    const repoRoot = f.repoRoot ?? f.root;
    const rel = relative(repoRoot, f.path) || f.path;
    const path = literalLabelPath(f.path);
    const edit: LockPathEdit = { op: "lock-path", path, level: "no-model" };
    const findingKey = workspaceFindingKey(path);
    const labelled = resolvePathLabel(f.path, law.pathLabels, opts.home);
    const judged = labelled !== null && labelled.level !== "public" ? ({ verdict: "covered" } as const) : judgeEdits(law, [edit], opts.now);
    if (judged.verdict === "covered") {
      out.covered.push({ repoRoot, paths: [rel], blobs: [], why: "law" });
      continue;
    }
    if (judged.verdict !== "ok") {
      out.dropped.push({ findingKey, repoRoot, why: judged.verdict, problems: judged.problems });
      continue;
    }
    out.suggestions.push({
      findingKey,
      source: "workspace",
      repoRoot,
      edits: judged.edits,
      sentence: suggestionSentence(judged.edits, { home: opts.home }),
      evidence: {
        paths: [rel],
        blobs: [],
        findings: [{
          blob: "", paths: [rel], firstCommit: null, lastCommit: null,
          inHead: false, inIndex: false, stillPresent: true,
          detectors: f.detectors.map(detectorView),
        }],
        historyOnly: false,
      },
      impact: { historicalVersions: 0, workingTreeChanges: true, files: [rel] },
      historyOnly: false,
      rotate: false,
    });
  }
  out.suggestions.sort((a, b) => a.findingKey.localeCompare(b.findingKey));
  return out;
}

// ── the past-sessions generator (plan 17 §3 item 13) ─────────────────────────

/** The dedup key of a past-sessions suggestion: `past-sessions:path:<literal
 *  path>` (a hash past 512 characters, as for the others). */
export function pastSessionsFindingKey(literalPath: string): string {
  const key = `past-sessions:path:${literalPath}`;
  return key.length <= 512 ? key : `past-sessions:sha256:${createHash("sha256").update(`path:${literalPath}`).digest("hex")}`;
}

/** One file `mandu scan` found a key of in the agents' past sessions, as the
 *  arbiter verified it (transcript-suggestions.ts `verifyScanFile`). */
export interface PastSessionsFile {
  /** Absolute. */
  path: string;
  /** The nearest work tree above the file and below HOME, else its folder. */
  repoRoot: string;
  /** The key names the arbiter read in the file and the scan named. */
  names: string[];
  sessions: number;
  last: string | null;
}

/**
 * Plan 17 §3 item 13: files whose key reached the AI in a past session and
 * that nothing protects → one `lock-path { path, level: "no-model" }`
 * suggestion per file, source `past-sessions`, through the tightening check.
 * A file the catalog or a label protects now (`isCovered`, the walk's
 * coverage check), or one the law labels above public, is covered. The
 * evidence is the file and `pastSessions` (names and counts); `rotate` is
 * TRUE: the key did leave the machine. Pure over `isCovered`.
 */
export function suggestPastSessionEdits(
  files: readonly PastSessionsFile[],
  law: SuggestLaw,
  opts: { home?: string; now?: number; isCovered?: (absPath: string) => boolean } = {},
): SuggestEditsResult {
  const out: SuggestEditsResult = { suggestions: [], covered: [], dropped: [] };
  const done = new Set<string>();
  for (const f of files) {
    if (done.has(f.path) || !isAbsolute(f.path)) continue;
    done.add(f.path);
    const rel = relative(f.repoRoot, f.path) || f.path;
    const path = literalLabelPath(f.path);
    const edit: LockPathEdit = { op: "lock-path", path, level: "no-model" };
    const findingKey = pastSessionsFindingKey(path);
    const labelled = resolvePathLabel(f.path, law.pathLabels, opts.home);
    const judged = opts.isCovered?.(f.path) === true || (labelled !== null && labelled.level !== "public")
      ? ({ verdict: "covered" } as const)
      : judgeEdits(law, [edit], opts.now);
    if (judged.verdict === "covered") {
      out.covered.push({ repoRoot: f.repoRoot, paths: [rel], blobs: [], why: "law" });
      continue;
    }
    if (judged.verdict !== "ok") {
      out.dropped.push({ findingKey, repoRoot: f.repoRoot, why: judged.verdict, problems: judged.problems });
      continue;
    }
    out.suggestions.push({
      findingKey,
      source: "past-sessions",
      repoRoot: f.repoRoot,
      edits: judged.edits,
      sentence: suggestionSentence(judged.edits, { home: opts.home }),
      evidence: {
        paths: [rel],
        blobs: [],
        findings: [],
        historyOnly: false,
        pastSessions: { names: [...f.names], sessions: f.sessions, last: f.last },
      },
      impact: { historicalVersions: 0, workingTreeChanges: true, files: [rel] },
      historyOnly: false,
      rotate: true,
    });
  }
  out.suggestions.sort((a, b) => a.findingKey.localeCompare(b.findingKey));
  return out;
}

// ── the sensitivity-label generator (plan 14 §14.1) ──────────────────────────

/** The dedup key of a label suggestion: `sensitivity-label:<literal path>`
 *  (a hash past 512 characters, as for the others). */
export function labelFindingKey(literalPath: string): string {
  const key = `sensitivity-label:${literalPath}`;
  return key.length <= 512 ? key : `sensitivity-label:sha256:${createHash("sha256").update(`path:${literalPath}`).digest("hex")}`;
}

/** A level in the Rules page's words (dashboard policy-proposals.ts `editRow`). */
const LEVEL_CLAUSE: Readonly<Record<string, string>> = {
  "no-model": "a secret no AI may read",
  "local-model": "a secret only your own AI may read",
  "any-model": "a secret any AI may read when it asks",
};

/** "Make ~/proj/q3-board.docx a secret no AI may read: its sensitivity
 *  label is Highly Confidential" (the MAPPING's name, never the file's). */
export function labelSentence(path: string, level: string, name: string, home?: string): string {
  const shown = displayPath(path, home);
  return `Make ${shown} ${LEVEL_CLAUSE[level] ?? "a secret"}: its sensitivity label is ${name.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")}`;
}

/**
 * The check a lock below `no-model` meets instead of the tightening check
 * (§14.1 as built): the delta calls ANY new lock below no-model a relaxation,
 * because it overrides the secret catalog under it. A label suggestion's lock
 * is on one literal file the walk found NOT protected (it was opened), so
 * the one relaxation it may carry is exactly that: a new label on its own
 * path, where the law's document has none. Anything else (a lock that
 * replaces an existing label, a second change, an invalid list) is refused.
 * Such a suggestion is `humanOnly`: filed for review, applied only by a
 * person on the admin channel, where `protectedNow` is checked again.
 */
export function judgeHumanLabelLock(
  law: { specId: InboundSpecId; document: PolicyFileConfig | null },
  edit: LockPathEdit,
  now?: number,
): { verdict: "ok" } | { verdict: "covered" } | { verdict: "invalid" | "relaxes"; problems: string[] } {
  const ev = evaluateEdits(law, [edit], now !== undefined ? { now } : {});
  if (!ev.ok) return { verdict: "invalid", problems: ev.problems };
  const id = pathIdentity(edit.path);
  const existing = (law.document?.paths ?? []).some((p) => pathIdentity(p.path) === id);
  if (existing) return { verdict: "relaxes", problems: [`${edit.path} already has a label of its own; a scan does not change it to ${edit.level}`] };
  if (ev.delta.tightenings.length === 0 && ev.delta.relaxations.length === 0) return { verdict: "covered" };
  const own = ev.delta.relaxations.filter((r) => r.facet === "paths");
  if (ev.delta.tightenings.length > 0 || own.length !== 1 || ev.delta.relaxations.length !== 1) {
    return { verdict: "relaxes", problems: ev.delta.relaxations.map((r) => r.detail) };
  }
  return { verdict: "ok" };
}

/**
 * Plan 14 §14.1: labelled Office files (secret-workspace-scan.ts, S4) →
 * one `lock-path { path, level }` suggestion per file, at the STRICTEST
 * mapped level of its enabled labels (`strictestMapping`; a mapping with a
 * `site` holds only for that tenant). `public` or no mapping suggests
 * nothing. A path the law already labels above `public` is covered. A
 * `no-model` lock goes through the tightening check (`judgeEdits`); a lower
 * one through `judgeHumanLabelLock` and is filed `humanOnly`. The sentence
 * names the MAPPING's name; the evidence carries the label's ids and that
 * name, never the file's text. `rotate: false`. Pure.
 */
export function suggestLabelEdits(
  findings: readonly SensitivityLabelFinding[],
  mapping: readonly LabelMappingEntry[],
  law: SuggestLaw,
  opts: { home?: string; now?: number } = {},
): SuggestEditsResult {
  const out: SuggestEditsResult = { suggestions: [], covered: [], dropped: [] };
  const done = new Set<string>();
  for (const f of findings) {
    if (done.has(f.path) || !isAbsolute(f.path)) continue;
    done.add(f.path);
    const m = strictestMapping(f.labels, mapping);
    if (m === null || m.level === "public") continue;
    const repoRoot = f.repoRoot;
    const rel = relative(repoRoot, f.path) || f.path;
    const path = literalLabelPath(f.path);
    const edit: LockPathEdit = { op: "lock-path", path, level: m.level };
    const findingKey = labelFindingKey(path);
    const labelled = resolvePathLabel(f.path, law.pathLabels, opts.home);
    if (labelled !== null && labelled.level !== "public") {
      out.covered.push({ repoRoot, paths: [rel], blobs: [], why: "law" });
      continue;
    }
    const humanOnly = m.level !== "no-model";
    const judged = humanOnly ? judgeHumanLabelLock(law, edit, opts.now) : judgeEdits(law, [edit], opts.now);
    if (judged.verdict === "covered") {
      out.covered.push({ repoRoot, paths: [rel], blobs: [], why: "law" });
      continue;
    }
    if (judged.verdict !== "ok") {
      out.dropped.push({ findingKey, repoRoot, why: judged.verdict, problems: judged.problems });
      continue;
    }
    const decided = f.labels.find((l) => l.id === m.id && (m.site === null || l.site === m.site)) ?? { id: m.id, site: m.site };
    out.suggestions.push({
      findingKey,
      source: "sensitivity-label",
      repoRoot,
      edits: [edit],
      sentence: labelSentence(f.path, m.level, m.name, opts.home),
      evidence: {
        paths: [rel],
        blobs: [],
        findings: [],
        historyOnly: false,
        label: { id: decided.id, site: decided.site, name: m.name, level: m.level, ...(m.adminFile !== undefined ? { adminFile: m.adminFile } : {}) },
      },
      impact: { historicalVersions: 0, workingTreeChanges: true, files: [rel] },
      historyOnly: false,
      rotate: false,
      ...(humanOnly ? { humanOnly: true } : {}),
    });
  }
  out.suggestions.sort((a, b) => a.findingKey.localeCompare(b.findingKey));
  return out;
}
