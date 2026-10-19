/**
 * policy-suggest — `mandu policy suggest` and the launch-time notice
 * (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md §5.2, §5.3,
 * §5.5).
 *
 * The arbiter scans the repository's git history (S1), the files on disk
 * under the roots (S2, the workspace scan, §13) and the sensitivity labels
 * Office wrote into documents there (S4, §14.1: through the person's
 * `sensitivity_labels:` mapping), turns what the law does not cover into
 * typed edits (`lock-path` / `lock-blob`) and files each as a SUGGESTION
 * that waits for a human. This module is the terminal's review of them:
 *
 *   mandu policy suggest              scan, then one screen per suggestion:
 *                                     [a]pply [s]kip [p]olicy.yaml lines [?] [q]uit
 *   mandu policy suggest --dry-run    the review, nothing applied
 *   mandu policy suggest --json       the suggestions as JSON, no questions
 *   mandu policy suggest --apply-all  every applicable one, after ONE typed
 *                                     confirmation on a terminal (refused without)
 *   mandu policy suggest --home       also the home folder's configuration files
 *   mandu policy suggest --model names
 *                                     then (plan 14 §14.5, behind
 *                                     MANDU_EXPERIMENTAL_POLICY_MODEL=1 until the
 *                                     quality bar is met) ask a model to shape
 *                                     rules from the file NAMES: the arbiter builds
 *                                     and keeps the request, this command shows it
 *                                     ([v]iew the names [y]es [N]o) and sends it
 *                                     only on yes (no terminal: `--yes-send
 *                                     <digest>` from a `--dry-run --json` preview)
 *   mandu policy suggest --model contents [--endpoint <name>]
 *                                     the same for the TEXT of documents (plan 14
 *                                     §14.11, behind the same flag): only to a
 *                                     model declared local: true (the arbiter
 *                                     refuses any other before anything is read);
 *                                     the preview lists the files and their byte
 *                                     counts ([v]iew the files [y]es [N]o), never
 *                                     their text
 *
 * WHO MAY DO WHAT (§5.2). Apply is `applySuggestion` on the DATA socket: the
 * arbiter applies it only as a pure tightening of the law in force, and
 * records it as the agent's channel's (`agent-tighten`, §14.14). "Not a
 * secret" withholds protection, so it is ADMIN-ONLY and the terminal, which
 * speaks on the channel the AI's own programs can reach, does not offer it:
 * the review says once that dismissing is done in the dashboard. A
 * sensitivity-label suggestion below no-model (`humanOnly`, §14.1) is shown
 * with Skip only and the words "apply it in the dashboard".
 *
 * The command is an EXPLICIT scan, so it asks the arbiter to count the
 * Office files' labels even with no mapping (`countLabels`, §14.1): the
 * header then says how many files carry a label nobody mapped. The launch's
 * call never asks (no Office file is opened there until a mapping exists).
 *
 * NO VALUE EVER CROSSES HERE: a SuggestionView carries paths, blob ids,
 * commits, the detector in plain words and the scan's fixed MASK (a format's
 * public prefix, an assignment's name, a key block's header), never a
 * character of a key's body. Every string from the wire is still stripped of
 * control characters before it reaches the terminal (a file name in an
 * agent-built repository could carry an escape sequence).
 *
 * The arbiter: the resident one when it answers with the secrets axis ON
 * (doctor-secrets.ts `realDoctorSecretsDeps().arbiter`); otherwise a
 * THROWAWAY on a private socket can scan and show, but its suggestions die
 * with it, so applying there is refused with a message that says why.
 *
 * Every host seam (the arbiter, the keys, the terminal test) is injected, so
 * the review is unit-tested with scripted keys and no arbiter.
 *
 * Mandu-new (no reference origin).
 */
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { runClassifierPack } from "./classifier-pack-command.js";
import { historyCallTimeoutMs, realDoctorSecretsDeps, type DryRunArbiter } from "./doctor-secrets.js";
import { ndjsonCall } from "./secret-setup.js";
import type { Layout } from "./services/layout.js";

type Env = Record<string, string | undefined>;

// ── the wire (a narrow mirror of arbiter/ipc/protocol.ts SuggestionView,
//    SuggestPolicyResult and ApplySuggestionResult; the packages ship
//    standalone) ──────────────────────────────────────────────────────────────

export type SuggestionEditWire =
  | { op: "lock-path"; path: string; level: string; bindings?: string[]; recursive?: boolean }
  | { op: "lock-blob"; blob: string; level: string; note?: string };

export interface SuggestionDetectorWire {
  kind: "content-shape" | "catalog-path";
  rule: string;
  /** The scan's fixed mask; for a catalog hit, the path. Never a value. */
  mask: string;
  /** The detector in plain words. */
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

export interface SuggestionViewWire {
  id: string;
  kind: "suggestion";
  status: "pending" | "approved" | "denied" | "superseded";
  requestedBy: string;
  findingKey: string;
  /** "git-history" (S1), "workspace" (S2, §13) or "sensitivity-label" (S4,
   *  §14.1): a workspace suggestion has one path, no commits (`blob: ""`,
   *  both commits null), `rotate: false`; a sensitivity-label one has one
   *  path, no finding entry and `evidence.label`. "model-names" (§14.10): a
   *  rule the names-only model shaped; its facts in `model`, its evidence
   *  one path and no finding. "model-contents" (§14.11): a document your own
   *  model read; one path, `model` facts, `humanOnly` below no-model. */
  source: "git-history" | "workspace" | "sensitivity-label" | "model-names" | "model-contents";
  repoRoot: string;
  edits: SuggestionEditWire[];
  sentence: string;
  evidence: {
    paths: string[]; blobs: string[]; findings: SuggestionFindingWire[]; historyOnly: boolean;
    /** S4: the label and the MAPPING's name for it (never the file's). */
    label?: { id: string; site: string | null; name: string; level: string; adminFile?: string };
  };
  impact: { historicalVersions: number; workingTreeChanges: boolean; files: string[] };
  historyOnly: boolean;
  rotate: boolean;
  /** S4: a level below no-model, which only a person applies, in the
   *  dashboard (absent from an older arbiter: false). */
  humanOnly?: boolean;
  /** `source: "model-names"` only (§14.4): the model's name, its answer as
   *  enums, the arbiter's words for the reason, the pending suggestions a
   *  folder rule groups. */
  model?: ModelFactsWire;
  applicable: boolean;
  createdAt: number;
  resolvedAt: number | null;
  resolvedBy: string | null;
  changeId: string | null;
  supersededBy: string | null;
}

export interface SuggestCountsWire {
  findings: number; suggested: number; filed: number; alreadyPending: number; dismissed: number;
  overCap: number; covered: number; dropped: number; superseded: number;
}

export interface SuggestPolicyWire {
  axis: boolean;
  running: boolean;
  suggestions: SuggestionViewWire[];
  filed: string[];
  covered: Array<{ repoRoot: string; paths: string[]; blobs: string[]; why: "protected-now" | "law" }>;
  counts: SuggestCountsWire;
  scan: {
    repos: Array<{ root: string; repoRoot: string | null; reason?: string }>;
    counts: { blobs: number; scanned: number; classified: number };
    capped: { lines: string[] };
    ms: number;
  } | null;
  /** The workspace scan (plan 14 §13.3) without its findings; null while
   *  running, with the axis OFF, or when it was not asked for. An older
   *  arbiter omits it. */
  workspaceScan?: WorkspaceScanWire | null;
  /** §5.5: when a finished scan of every source last covered the roots (epoch
   *  ms), null when none did in the arbiter's run; with `running: true` and
   *  a time, `suggestions` are what that earlier scan left. An older arbiter
   *  omits it. */
  lastScanAt?: number | null;
}

export interface WorkspaceScanWire {
  roots: Array<{ root: string; tier: "workspace" | "home"; reason?: string }>;
  counts: { examined: number; read: number; cached: number; bytes: number; covered: number };
  capped: {
    tooBig: number; overTotal: number; overTime: number; overFiles: number; binary: number;
    symlinks: number; unreadable: number; special: number; depth: number; worktrees?: number; lines: string[];
  };
  limits: { fileMaxBytes: number; totalMaxBytes: number; maxFiles: number; timeoutMs: number };
  ms: number;
  /** S4 (§14.1): the label read's summary; null when not asked for, absent
   *  from an older arbiter. */
  labels?: LabelScanWire | null;
}

/** What the label read did (arbiter sensitivity-labels.ts
 *  `SensitivityLabelScanSummary`, the fields the terminal reads). */
export interface LabelScanWire {
  mode: "mapped" | "count" | "off";
  examined: number;
  read: number;
  cached: number;
  covered: number;
  files: number;
  mapped: number;
  unmappedFiles: number;
  unmapped: Array<{ id: string; site: string | null; files: number }>;
  unmappedMore: number;
  encrypted: number;
  unreadable: number;
}

/** A model suggestion's facts (arbiter policy-model.ts ModelSuggestionFacts). */
export interface ModelFactsWire {
  endpoint: string;
  level: "any-model" | "local-model" | "no-model";
  reason: string;
  reasonWords: string;
  candidate: "file" | "folder";
  files: number;
  covers: string[];
}

/** Where a model request goes (arbiter policy-model.ts ModelDestination). */
export interface ModelDestinationWire {
  kind: "declared" | "default";
  name: string;
  location: "local" | "external";
  placement: "host" | "network";
  vendor: string;
}

/** `modelSuggestPreview`'s answer (arbiter protocol.ts ModelSuggestPreviewResult). */
export interface ModelPreviewWire {
  axis: boolean;
  tier: "names" | "contents";
  digest: string;
  destination: ModelDestinationWire;
  roots: Array<{ index: number; root: string; files: number }>;
  items: number;
  bytes: number;
  requests: number;
  names: string[];
  /** T2 (§14.11): the documents whose head is sent, with the bytes sent
   *  (never their text); absent from an older arbiter. */
  files?: Array<{ root: number; name: string; bytes: number; truncated: boolean }>;
  left: {
    covered: number; labelled: number; tooLong: number; personal: number; overCap: number; detector: number; registered: number;
    /** T2: a detector flagged the file in the walk; the file was not read whole. */
    flagged?: number; unread?: number;
  };
  promptVersion: string;
  confine: { live: boolean; note?: string };
  expiresAt: number;
  walk: { examined: number; covered: number; capped: string[] };
}

/** `modelSuggest`'s answer (arbiter protocol.ts ModelSuggestResult). */
export interface ModelRunWire {
  axis: boolean;
  running: boolean;
  digest: string;
  destination: ModelDestinationWire | null;
  sent: { requests: number; items: number; bytes: number };
  counts: {
    rules: number; kept: number; dropped: number; merged: number; tooBroad: number; covered: number;
    filed: number; alreadyPending: number; dismissed: number; overCap: number; failedRequests: number;
    /** T2: documents answered `public` (absent from an older arbiter). */
    public?: number;
  };
  filed: string[];
  suggestions: SuggestionViewWire[];
  error: string | null;
  ms: number;
}

/** What a `suggestPolicy` call asks besides the roots and the budget. */
export interface SuggestOptsWire {
  /** Also walk the home folder (its configuration files only, §13.1). */
  includeHome?: boolean;
  /** Count the Office files' sensitivity labels even with no mapping
   *  (§14.1): the explicit command sets it; the launch never does. */
  countLabels?: boolean;
  /** §5.5, the launch only: when a scan of these roots already finished,
   *  answer at once from what it left and scan in the background. */
  answerFromEarlier?: boolean;
}

export type ApplySuggestionWire =
  | { applied: true; changeId: string; suggestion: SuggestionViewWire }
  | { applied: false; refused: "covered" | "relaxes" | "invalid" | "stale" | "unsupported"; problems: string[]; suggestion: SuggestionViewWire };

// ── flags ────────────────────────────────────────────────────────────────────

export interface PolicySuggestArgs {
  dryRun: boolean;
  json: boolean;
  applyAll: boolean;
  /** --no-color given (colour is also off off a terminal and under NO_COLOR). */
  noColor: boolean;
  /** --home: also scan the home folder's configuration files (§13.1). */
  home: boolean;
  /** --root values, as given (resolved against the cwd later). */
  roots: string[];
  /** --model names|contents (plan 14 §14.5): null = no model (T0). */
  model: "names" | "contents" | null;
  /** --endpoint <name>: a declared policy.yaml `models:` entry. */
  endpoint: string | null;
  /** --yes-send <digest>: the consent given ahead, from a `--dry-run --json`
   *  preview; sends only when this run's preview has the same digest. */
  yesSend: string | null;
  /** Usage errors: non-empty = exit 2, nothing done. */
  errors: string[];
}

/** Parse `mandu policy suggest`'s own args (after the `suggest` word). Pure. */
export function parsePolicySuggestArgs(rest: string[]): PolicySuggestArgs {
  const a: PolicySuggestArgs = { dryRun: false, json: false, applyAll: false, noColor: false, home: false, roots: [], model: null, endpoint: null, yesSend: null, errors: [] };
  const value = (t: string, flag: string, i: number): { v: string | undefined; next: number } =>
    t === flag ? { v: rest[i + 1], next: i + 1 } : { v: t.slice(flag.length + 1), next: i };
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i]!;
    if (t === "--dry-run" || t === "-n") a.dryRun = true;
    else if (t === "--json") a.json = true;
    else if (t === "--apply-all") a.applyAll = true;
    else if (t === "--no-color") a.noColor = true;
    else if (t === "--home") a.home = true;
    else if (t === "--root") {
      const v = rest[++i];
      if (v === undefined || v === "") a.errors.push("--root needs a directory");
      else a.roots.push(v);
    } else if (t.startsWith("--root=")) {
      const v = t.slice("--root=".length);
      if (v === "") a.errors.push("--root needs a directory");
      else a.roots.push(v);
    } else if (t === "--model" || t.startsWith("--model=")) {
      const { v, next } = value(t, "--model", i);
      i = next;
      if (v === "names" || v === "contents") a.model = v;
      else a.errors.push("--model needs names or contents");
    } else if (t === "--endpoint" || t.startsWith("--endpoint=")) {
      const { v, next } = value(t, "--endpoint", i);
      i = next;
      if (v === undefined || v === "") a.errors.push("--endpoint needs the name of a model declared in policy.yaml");
      else a.endpoint = v;
    } else if (t === "--yes-send" || t.startsWith("--yes-send=")) {
      const { v, next } = value(t, "--yes-send", i);
      i = next;
      if (v === undefined || !/^[0-9a-f]{64}$/.test(v)) a.errors.push("--yes-send needs the digest a --dry-run --json preview printed");
      else a.yesSend = v;
    } else a.errors.push(`unknown option '${t}'`);
  }
  if (a.endpoint !== null && a.model === null) a.errors.push("--endpoint picks the model for --model names or --model contents; give --model too");
  if (a.yesSend !== null && a.model === null) a.errors.push("--yes-send sends a --model preview; give --model names or --model contents too");
  if (a.yesSend !== null && a.dryRun) a.errors.push("--yes-send sends; --dry-run sends nothing: pick one");
  if (a.model !== null && a.applyAll) a.errors.push("--model asks before it sends; --apply-all applies without looking: run them separately");
  if (a.applyAll && a.dryRun) a.errors.push("--apply-all and --dry-run contradict each other");
  if (a.applyAll && a.json) a.errors.push("--apply-all asks a question; --json asks none: pick one");
  return a;
}

/** How the command runs, from the flags and whether there is a terminal. Pure. */
export type SuggestMode = "json" | "review" | "interactive" | "apply-all";

export function suggestMode(a: PolicySuggestArgs, tty: boolean): { mode: SuggestMode; note: string | null; refuse: string | null } {
  if (a.json) return { mode: "json", note: null, refuse: null };
  if (a.applyAll) {
    return tty
      ? { mode: "apply-all", note: null, refuse: null }
      : { mode: "apply-all", note: null, refuse: "--apply-all needs a terminal to confirm on; nothing was scanned or applied (review with --dry-run, or run it in a terminal)" };
  }
  if (a.dryRun) return { mode: "review", note: null, refuse: null };
  if (!tty) return { mode: "review", note: "no terminal to ask on: showing the review only, as with --dry-run; nothing is applied", refuse: null };
  return { mode: "interactive", note: null, refuse: null };
}

// ── rendering (pure) ─────────────────────────────────────────────────────────

/** Strip control characters (C0, DEL, C1) from a wire string before it
 *  reaches the terminal. */
export function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");
}

const tilde = (p: string, home: string): string =>
  p === home ? "~" : home !== "" && p.startsWith(home.endsWith("/") ? home : home + "/") ? "~/" + p.slice(home.length).replace(/^\/+/, "") : p;

const short = (c: string | null): string => (c === null ? "?" : c.slice(0, 8));
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

export interface Palette {
  bold: (s: string) => string;
  dim: (s: string) => string;
  warn: (s: string) => string;
  ok: (s: string) => string;
}

export function palette(color: boolean): Palette {
  const w = (a: string, b: string) => (s: string) => (color ? `\u001b[${a}m${s}\u001b[${b}m` : s);
  return { bold: w("1", "22"), dim: w("2", "22"), warn: w("33", "39"), ok: w("32", "39") };
}

const INDENT = "      ";

/** One detector hit in plain words: what it looks like, the mask, where. */
export function detectorLine(d: SuggestionDetectorWire): string {
  if (d.kind === "catalog-path") return `${clean(d.words)}: ${clean(d.mask)}`;
  return `looks like a ${clean(d.words)} · ${clean(d.mask)}${d.line !== undefined ? ` (line ${d.line})` : ""}`;
}

/** Where a version of the secret sits in the history. */
export function commitLine(f: SuggestionFindingWire): string {
  const where = f.paths.length > 0 ? clean(f.paths[0]!) + (f.paths.length > 1 ? ` (+${f.paths.length - 1} more name${f.paths.length === 2 ? "" : "s"})` : "") : "(no path)";
  const now = [f.inHead ? "in the current commit" : "", f.inIndex && !f.inHead ? "staged" : ""].filter(Boolean);
  const when = f.firstCommit !== null
    ? `added ${short(f.firstCommit)}${f.lastCommit !== null && f.lastCommit !== f.firstCommit ? `, ${f.inHead ? "last changed" : "removed or replaced"} ${short(f.lastCommit)}` : ""}`
    : f.inIndex ? "staged, in no commit" : "commit not traced";
  return `${where}: ${when}${now.length > 0 ? ` (${now.join(", ")})` : ""}`;
}

/** What applying it hides. `platform` darwin: a macOS launch makes a
 *  protected file unreadable (no placeholder), and the history part holds
 *  on Linux only (`MACOS_HISTORY_LINE` says so beside it). */
export function impactLine(v: SuggestionViewWire, platform: string = "linux"): string {
  const i = v.impact;
  const found = plural(i.historicalVersions, "old version", "old versions");
  const pathLock = v.edits.some((e) => e.op === "lock-path");
  const file = v.evidence.paths.length > 0 ? clean(v.evidence.paths[0]!) : "the file";
  // A blob lock hides exactly the old versions; the current file (which no
  // longer holds the key) stays readable (plan 14 §8.2).
  const hist = pathLock ? `every committed version of the file (${found} found)` : `${found} of ${file}`;
  const now = i.workingTreeChanges && i.files.length > 0
    ? `and now ${i.files.map(clean).join(", ")} (${platform === "darwin" ? "the AI cannot read it" : "the AI sees a placeholder in its place"})`
    : pathLock ? "the working tree is unchanged" : `the current ${file} stays readable to the AI`;
  return `hides: ${hist}${platform === "darwin" ? " (on Linux)" : ""} · ${now}`;
}

/** Does applying the suggestion hide committed versions (a history-scan
 *  suggestion: a gone path's `lock-path`, a `lock-blob`, a present file's
 *  history)? A workspace (§13.4), sensitivity-label (§14.1) or model
 *  (§14.10, §14.11) suggestion promises only the file or folder. */
export function hidesHistory(v: SuggestionViewWire): boolean {
  return v.source === "git-history";
}

/** macOS (confidentiality.md §7.3): a history lock is enforced only by a
 *  Linux launch (plan 14 §8, §11.1); the review says so under each history
 *  suggestion. */
export const MACOS_HISTORY_LINE =
  "on macOS the committed versions stay readable to programs the AI runs (git show, git log -p): only a Linux launch hides them; rotate the key";

/** macOS: said after a history suggestion is applied. */
export const MACOS_APPLIED_NOTE = "On macOS it hides the committed versions on Linux launches only: here they stay readable.";

export const ROTATE_LINE = "This key was exposed. Rotate it: a rule keeps the AI from reading it from now on; it cannot undo a push or an earlier session.";
/** macOS: a rule hides no committed version there (plan 14 §11.3). */
export const MACOS_ROTATE_LINE = "This key was exposed. Rotate it: on macOS a rule does not keep the AI from reading its committed versions, and it cannot undo a push or an earlier session.";

/** A workspace finding (§13.4): nothing shows the key left the machine, so
 *  the advice is conditional. */
export const WORKSPACE_ROTATE_LINE = "If an AI session read this file before, rotate the key.";

/** What applying a workspace suggestion hides: the file, as an ordinary
 *  label that discovery confines from the next launch (§13.6). */
export const WORKSPACE_IMPACT_LINE = "hides: this file, from the next launch";

/** A sensitivity-label suggestion's evidence (§14.1): the words the
 *  dashboard's row uses, and the MAPPING's name. */
export const LABEL_SOURCE_LINE = "From the document's sensitivity label";
/** §14.1: the lock is an ordinary rule once applied, so a label lowered in
 *  Office later lowers nothing. The dashboard's row says the same
 *  (dashboard/src/view-model/suggestions.ts `LABEL_NOTE`). */
export const LABEL_LOWER_LINE = "If the label is lowered or removed in Office later, this rule stays as it is: change it in your policy if you want it lower.";


/** The screen for one suggestion (without the key prompt). Pure.
 *  `opts.platform` darwin: the history suggestion says it hides committed
 *  versions on Linux only (default: linux). */
export function renderSuggestion(v: SuggestionViewWire, i: number, n: number, opts: { home: string; color: boolean; platform?: string }): string {
  const platform = opts.platform ?? "linux";
  const c = palette(opts.color);
  const L: string[] = [];
  L.push(c.bold(`[${i}/${n}] ${clean(v.sentence)}`));
  L.push(`${INDENT}${c.dim(`in ${clean(tilde(v.repoRoot, opts.home))} · suggestion ${clean(v.id)}`)}`);
  if (v.source === "sensitivity-label") {
    // An Office document's label, mapped by the person (§14.1): no key, so
    // no hit, no commit line and no rotation advice.
    const lab = v.evidence.label;
    L.push(`${INDENT}${LABEL_SOURCE_LINE}${lab ? `: ${clean(lab.name)}${lab.adminFile ? ` (mapped by your administrator)` : ""}` : ""}`);
    L.push(`${INDENT}${WORKSPACE_IMPACT_LINE}`);
    L.push(`${INDENT}${c.dim(LABEL_LOWER_LINE)}`);
    return L.join("\n") + "\n";
  }
  if (v.source === "workspace") {
    // A file on disk now (§13.3): its hits (the sentence names the file), no
    // commit line, the file as the impact, and the softer rotation advice.
    for (const f of v.evidence.findings.slice(0, 1)) {
      for (const d of f.detectors.slice(0, 2)) L.push(`${INDENT}${detectorLine(d)}`);
      if (f.detectors.length > 2) L.push(`${INDENT}${c.dim(`+${f.detectors.length - 2} more hit${f.detectors.length === 3 ? "" : "s"} in this file`)}`);
    }
    L.push(`${INDENT}${WORKSPACE_IMPACT_LINE}`);
    L.push(`${INDENT}${WORKSPACE_ROTATE_LINE}`);
    return L.join("\n") + "\n";
  }
  if (v.source === "model-names") {
    // A rule the names-only model shaped (§14.4): who suggested it and why,
    // in the arbiter's words for the reason code, and what it hides.
    const m = v.model;
    L.push(`${INDENT}suggested by your model ${clean(m?.endpoint ?? "?")}: ${clean(m?.reasonWords ?? "looks sensitive")}, from the file names`);
    L.push(`${INDENT}${modelImpactLine(v)}`);
    return L.join("\n") + "\n";
  }
  if (v.source === "model-contents") {
    // A document your own model read (§14.11): who read it, the reason in
    // the arbiter's words, the level it asked for, what applying hides.
    const m = v.model;
    L.push(`${INDENT}suggested by your model ${clean(m?.endpoint ?? "?")}, which read the file on your side: ${clean(m?.reasonWords ?? "looks sensitive")}`);
    L.push(`${INDENT}${WORKSPACE_IMPACT_LINE}`);
    return L.join("\n") + "\n";
  }
  const SHOW = 3;
  for (const f of v.evidence.findings.slice(0, SHOW)) {
    for (const d of f.detectors.slice(0, 2)) L.push(`${INDENT}${detectorLine(d)}`);
    if (f.detectors.length > 2) L.push(`${INDENT}${c.dim(`+${f.detectors.length - 2} more hit${f.detectors.length === 3 ? "" : "s"} in this version`)}`);
    L.push(`${INDENT}${c.dim(commitLine(f))}`);
  }
  if (v.evidence.findings.length > SHOW) L.push(`${INDENT}${c.dim(`+${v.evidence.findings.length - SHOW} more version${v.evidence.findings.length - SHOW === 1 ? "" : "s"} (--json lists them all)`)}`);
  L.push(`${INDENT}${impactLine(v, platform)}`);
  if (platform === "darwin" && hidesHistory(v)) L.push(`${INDENT}${c.warn(MACOS_HISTORY_LINE)}`);
  if (v.rotate) L.push(`${INDENT}${c.warn(platform === "darwin" ? MACOS_ROTATE_LINE : ROTATE_LINE)}`);
  return L.join("\n") + "\n";
}

/** What applying a model suggestion hides (§14.4). Pure. */
export function modelImpactLine(v: SuggestionViewWire): string {
  const m = v.model;
  if (m?.candidate === "folder") {
    return `hides: this folder and everything in it (${plural(m.files, "file", "files")} the scan listed), from the next launch` +
      (m.covers.length > 0 ? `; closes the ${plural(m.covers.length, "suggestion", "suggestions")} it covers` : "");
  }
  return WORKSPACE_IMPACT_LINE;
}

/** Where a model runs, in words (§14.5). Pure. */
export function destinationWords(d: ModelDestinationWire): string {
  const where = d.location === "local"
    ? (d.placement === "host" ? "your own model, on this computer" : "your own model, on your organization's network")
    : (d.placement === "host" ? "an outside model, reached through this computer" : "outside this computer");
  return `${clean(d.name)} (${clean(d.vendor)}, ${where})`;
}

/** A byte count in the preview's words ("380 KB", "900 bytes"). Pure. */
export function kbWords(bytes: number): string {
  return bytes < 1024 ? `${num(bytes)} bytes` : `${num(Math.round(bytes / 1024))} KB`;
}

/** The consent line (§14.5): "This sends 312 file names from 2 folders to
 *  Claude (Anthropic, outside this computer)."; for T2 (§14.11): "This
 *  sends the text of 41 files (380 KB) to your own model ollama (this
 *  computer)." Pure. */
export function modelPreviewLine(p: ModelPreviewWire): string {
  if (p.tier === "contents") {
    const where = p.destination.placement === "host" ? "this computer" : "your organization's network";
    return `This sends the text of ${plural(p.items, "file", "files")} (${kbWords(p.bytes)}) to your own model ${clean(p.destination.name)} (${where}), ` +
      `one file per request, at most the first 16 KB of each.`;
  }
  return `This sends ${plural(p.items, "file or folder name", "file and folder names")} from ${plural(p.roots.length, "folder", "folders")} ` +
    `to ${destinationWords(p.destination)}, in ${plural(p.requests, "request", "requests")} (${num(p.bytes)} bytes). No file's content is sent.`;
}

/** What the preview left out and how the call is confined, one line each. Pure. */
export function modelPreviewNotes(p: ModelPreviewWire): string[] {
  const L: string[] = [];
  const l = p.left;
  if (p.tier === "contents") {
    const out = [
      l.covered + l.labelled > 0 ? `${plural(l.covered + l.labelled, "document", "documents")} your policy or a sensitivity label protects` : "",
      (l.flagged ?? 0) + l.detector + l.registered > 0 ? `${plural((l.flagged ?? 0) + l.detector + l.registered, "document that holds", "documents that hold")} something like a key` : "",
      (l.unread ?? 0) > 0 ? `${plural(l.unread ?? 0, "document", "documents")} the scan could not read whole (too large, binary, encrypted or unreadable)` : "",
      l.overCap > 0 ? `${plural(l.overCap, "document", "documents")} over the 200-file limit` : "",
    ].filter(Boolean);
    L.push("Only documents (.md .txt .rst .org .tex .csv .tsv .rtf .html, and the text of Word, Excel and PowerPoint files) your policy calls public are read; nothing is sent outside your own model.");
    if (out.length > 0) L.push(`Not sent: ${out.join(", ")}.`);
    L.push(p.confine.live ? "The call can reach only the model's own port (network confine live)." : `Note: ${clean(p.confine.note ?? "the network confine is unavailable")}.`);
    return L;
  }
  const kept = [
    l.covered + l.labelled > 0 ? `${plural(l.covered + l.labelled, "name", "names")} your policy protects` : "",
    l.detector + l.registered > 0 ? `${plural(l.detector + l.registered, "name", "names")} that look like a key` : "",
    l.personal > 0 ? `${plural(l.personal, "name", "names")} holding your home folder or user name` : "",
    l.tooLong > 0 ? `${plural(l.tooLong, "name", "names")} over 300 characters` : "",
    l.overCap > 0 ? `${plural(l.overCap, "name", "names")} over the 5,000-name limit` : "",
  ].filter(Boolean);
  if (kept.length > 0) L.push(`Not sent: ${kept.join(", ")}.`);
  L.push(p.confine.live ? "The call can reach only the model's own port (network confine live)." : `Note: ${clean(p.confine.note ?? "the network confine is unavailable")}.`);
  return L;
}

/** Every line the request carries, with which folder each `root <n>` is
 *  (the roots are shown here, never sent). Pure. */
export function renderModelNames(p: ModelPreviewWire, home: string): string {
  const L = p.roots.map((r) => `  root ${r.index} = ${clean(tilde(r.root, home))} (not sent)`);
  for (const n of p.names) L.push(`  ${clean(n)}`);
  return L.join("\n") + "\n";
}

/** Every file a T2 request reads, with its root and the bytes sent (the
 *  roots are shown here, never sent; no byte of any file's text). Pure. */
export function renderModelFiles(p: ModelPreviewWire, home: string): string {
  const L = p.roots.map((r) => `  root ${r.index} = ${clean(tilde(r.root, home))} (not sent)`);
  for (const f of p.files ?? []) L.push(`  root ${f.root}  ${clean(f.name)}  ${kbWords(f.bytes)}${f.truncated ? " (the first 16 KB)" : ""}`);
  return L.join("\n") + "\n";
}

/** The model run in one line. Pure. */
export function modelRunLine(r: ModelRunWire, tier: "names" | "contents" = "names"): string {
  const k = r.counts;
  if (r.error !== null && k.rules === 0) return `The model run did not complete: ${clean(r.error)}. Nothing was filed.`;
  if (tier === "contents") {
    const human = r.suggestions.filter((v) => v.humanOnly === true && r.filed.includes(v.id)).length;
    const parts = [
      `${plural(k.rules, "document", "documents")} answered`,
      `${num(k.filed)} filed for your review${human > 0 ? ` (${num(human)} only you can approve, in the dashboard)` : ""}`,
      `${num(k.public ?? 0)} not sensitive`,
      ...(k.covered > 0 ? [`${num(k.covered)} already covered`] : []),
      ...(k.alreadyPending > 0 ? [`${num(k.alreadyPending)} already waiting`] : []),
      ...(k.dismissed > 0 ? [`${num(k.dismissed)} dismissed before`] : []),
      ...(k.overCap > 0 ? [`${num(k.overCap)} over the 20 per folder`] : []),
      ...(k.dropped > 0 ? [`${num(k.dropped)} answers dropped (not a level and a reason)`] : []),
      ...(k.failedRequests > 0 ? [`${plural(k.failedRequests, "request", "requests")} failed`] : []),
    ];
    return `Your model answered: ${parts.join(", ")}.${r.error !== null ? ` (${clean(r.error)})` : ""}`;
  }
  const parts = [
    `${plural(k.rules, "rule", "rules")} came back`,
    `${num(k.filed)} filed for your review`,
    ...(k.tooBroad > 0 ? [`${num(k.tooBroad)} too broad`] : []),
    ...(k.covered > 0 ? [`${num(k.covered)} already covered`] : []),
    ...(k.alreadyPending > 0 ? [`${num(k.alreadyPending)} already waiting`] : []),
    ...(k.dismissed > 0 ? [`${num(k.dismissed)} dismissed before`] : []),
    ...(k.overCap > 0 ? [`${num(k.overCap)} over the 20 per folder`] : []),
    ...(k.dropped > 0 ? [`${num(k.dropped)} answer parts dropped (not a rule over a listed name)`] : []),
    ...(k.failedRequests > 0 ? [`${plural(k.failedRequests, "request", "requests")} failed`] : []),
  ];
  return `The model answered: ${parts.join(", ")}.${r.error !== null ? ` (${clean(r.error)})` : ""}`;
}

/** The consent prompt's key. Pure. */
export function readConsentKey(raw: string): "view" | "yes" | "no" {
  const k = raw.trim().toLowerCase()[0] ?? "";
  return k === "v" ? "view" : k === "y" ? "yes" : "no";
}

export const CONSENT_PROMPT = "[v]iew the names  [y]es  [N]o ";
/** T2's (§14.11): the files and their sizes, never their text. */
export const CONSENT_PROMPT_FILES = "[v]iew the files  [y]es  [N]o ";

/** Is the names-only model offered (§14.6: behind the flag until its
 *  quality bar is recorded)? Pure. */
export function modelOffered(env: Env): boolean {
  return (env["MANDU_EXPERIMENTAL_POLICY_MODEL"] ?? "") === "1";
}

export const MODEL_NOT_OFFERED =
  "--model names is not offered yet: its quality bar is not met (plan 14 §14.6). Set MANDU_EXPERIMENTAL_POLICY_MODEL=1 to try it anyway";
/** T2 (§14.6, §14.11): the same flag. */
export const CONTENTS_NOT_OFFERED =
  "--model contents is not offered yet: its quality bar is not settled (plan 14 §14.6). Set MANDU_EXPERIMENTAL_POLICY_MODEL=1 to try it anyway";

/** A YAML scalar: plain when that is unambiguous, else double-quoted (a JSON
 *  string is a valid YAML double-quoted scalar). */
export function yamlScalar(s: string): string {
  return /^[A-Za-z0-9_/.~+@-][A-Za-z0-9_/.~+@\\ -]*$/.test(s) && !/\s$/.test(s) ? s : JSON.stringify(s);
}

/** The exact policy.yaml lines the edits would add. Pure. */
export function policyYamlLines(v: SuggestionViewWire): string[] {
  const paths = v.edits.filter((e): e is Extract<SuggestionEditWire, { op: "lock-path" }> => e.op === "lock-path");
  const blobs = v.edits.filter((e): e is Extract<SuggestionEditWire, { op: "lock-blob" }> => e.op === "lock-blob");
  const L: string[] = [];
  if (paths.length > 0) {
    L.push("paths:");
    for (const e of paths) {
      L.push(`  - path: ${yamlScalar(clean(e.path))}`, `    level: ${clean(e.level)}`);
      if (e.bindings && e.bindings.length > 0) L.push(`    bindings: [${e.bindings.map((b) => yamlScalar(clean(b))).join(", ")}]`);
      if (e.recursive === false) L.push("    recursive: false");
    }
  }
  if (blobs.length > 0) {
    L.push("blobs:");
    for (const e of blobs) {
      L.push(`  - id: ${clean(e.blob)}`, `    level: ${clean(e.level)}`);
      if (e.note) L.push(`    note: ${JSON.stringify(clean(e.note))}`);
    }
  }
  return L;
}

/** A count with thousands separators ("1,204"). */
const num = (n: number): string => n.toLocaleString("en-US");

/** The workspace scan's part of the header: "1,204 files in ~/proj (38
 *  read, …, in 0.3 s)", or null when no root was walked. Pure. */
export function workspaceScanPhrase(w: WorkspaceScanWire, home: string): string | null {
  const walked = w.roots.filter((x) => x.reason === undefined);
  if (walked.length === 0) return null;
  const where = walked.map((x) => (x.tier === "home" ? `${clean(tilde(x.root, home))} (configuration files only)` : clean(tilde(x.root, home)))).join(", ");
  const k = w.counts;
  const detail = [
    `${num(k.read)} read`,
    ...(k.cached > 0 ? [`${num(k.cached)} unchanged since the last scan`] : []),
    ...(k.covered > 0 ? [`${num(k.covered)} already protected, not opened`] : []),
  ].join(", ");
  return `${num(k.examined)} ${k.examined === 1 ? "file" : "files"} in ${where} (${detail}, in ${(w.ms / 1000).toFixed(1)} s)`;
}

/** The scan's header: both scans named (§13.6), each cap in plain words.
 *  `platform` darwin: a covered history finding is covered on Linux only
 *  (a macOS launch hides no committed version). Pure. */
export function renderScanHeader(r: SuggestPolicyWire, roots: string[], home: string, platform: string = "linux"): string {
  const L: string[] = [];
  const repos = (r.scan?.repos ?? []).filter((x) => x.repoRoot !== null).map((x) => clean(tilde(x.repoRoot!, home)));
  const ws = r.workspaceScan ?? null;
  const wsPhrase = ws !== null ? workspaceScanPhrase(ws, home) : null;
  if (r.running) {
    L.push(`The scan of ${roots.map((p) => clean(tilde(p, home))).join(", ")} is still running in Mandu; showing what is waiting now. Run this again in a minute for the rest.`);
  } else if (repos.length === 0 && wsPhrase === null) {
    const why = r.scan?.repos[0]?.reason ?? ws?.roots[0]?.reason;
    L.push(`No git repository${ws !== null ? " or folder" : ""} to scan under ${roots.map((p) => clean(tilde(p, home))).join(", ")}${why ? ` (${clean(why)})` : ""}.`);
  } else {
    const s = r.scan;
    const k = r.counts;
    const parts = [
      ...(s !== null && repos.length > 0 ? [`the git history of ${repos.join(", ")} (${plural(s.counts.scanned, "file version", "file versions")} read in ${(s.ms / 1000).toFixed(1)} s)`] : []),
      ...(wsPhrase !== null ? [wsPhrase] : []),
    ];
    L.push(`Scanned ${parts.join(" and ")}: ${plural(k.findings, "possible key", "possible keys")} found, ${k.covered} already covered.`);
    if (s !== null && repos.length === 0) {
      const why = s.repos[0]?.reason;
      L.push(`  · no git history scanned${why ? `: ${clean(why)}` : ""}`);
    }
    for (const line of s?.capped.lines ?? []) L.push(`  · not scanned: ${clean(line)}`);
    for (const x of ws?.roots ?? []) if (x.reason !== undefined) L.push(`  · not scanned: ${clean(tilde(x.root, home))} (${clean(x.reason)})`);
    for (const line of ws?.capped.lines ?? []) L.push(`  · not scanned: ${clean(line)}`);
    const lab = ws?.labels ?? null;
    if (lab !== null && lab.mode !== "off" && lab.files > 0) {
      L.push(`  · ${plural(lab.files, "Office file carries", "Office files carry")} a sensitivity label${lab.mapped > 0 ? ` (${num(lab.mapped)} mapped in your policy)` : ""}`);
    }
    if (lab !== null && lab.unmappedFiles > 0) {
      L.push(`  · ${plural(lab.unmappedFiles, "file carries", "files carry")} a sensitivity label you have not mapped: map ${lab.unmapped.length + lab.unmappedMore === 1 ? "it" : "them"} in the dashboard (Settings › Sensitivity labels) or under sensitivity_labels: in policy.yaml`);
    }
    if (k.dismissed > 0) L.push(`  · ${plural(k.dismissed, "finding was", "findings were")} marked "not a secret" in the dashboard before, and ${k.dismissed === 1 ? "is" : "are"} not suggested again`);
    if (k.overCap > 0) L.push(`  · ${k.overCap} more not listed: at most 20 wait per repository; apply or dismiss some and scan again`);
    for (const cv of r.covered.slice(0, 5)) {
      const where = platform === "darwin" && cv.blobs.length > 0 ? " on Linux; on macOS its committed versions stay readable" : "";
      L.push(`  ✓ ${cv.paths.map(clean).join(", ") || cv.blobs.map((b) => short(b)).join(", ")}: covered (${cv.why === "protected-now" ? "the file is protected now" : "your policy already hides it"}${where})`);
    }
    if (r.covered.length > 5) L.push(`  ✓ +${r.covered.length - 5} more covered`);
  }
  return L.join("\n") + "\n";
}

export const DISMISS_NOTE =
  "Not a secret? Say so in the dashboard (Rules › Keys Mandu found). Dismissing withholds protection, " +
  "so it is not offered here: this command talks to Mandu on the channel the AI's own programs can reach.";

export const KEY_HELP = [
  "  a  apply: add the rule to your policy (a tightening; undo it in the dashboard, under Rule changes in Approvals)",
  "  s  skip: leave it waiting (it stays in the dashboard's Keys Mandu found)",
  "  p  show the policy.yaml lines applying it would add",
  "  q  quit: leave this and the rest waiting",
  "  ?  this help",
].join("\n") + "\n";

/** JSON for the terminal: JSON.stringify escapes C0 controls in strings but
 *  leaves DEL and C1 (U+007F-U+009F, where U+009B is an 8-bit CSI) raw, so
 *  those are escaped too. The text parses to the same value. Pure. */
export function jsonText(v: unknown): string {
  return JSON.stringify(v, null, 2).replace(/[\u007f-\u009f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** The prompt line for one suggestion. Pure. */
export function promptLine(canApply: boolean): string {
  return canApply ? `${INDENT}[a]pply  [s]kip  [p]olicy.yaml lines  [q]uit  [?] ` : `${INDENT}[s]kip  [p]olicy.yaml lines  [q]uit  [?] `;
}

/** A key as the review reads it. Pure. */
export type ReviewKey = "apply" | "skip" | "policy" | "help" | "quit" | "other";

export function readReviewKey(raw: string): ReviewKey {
  if (raw === "" || raw === "\u0003" || raw === "\u0004") return "quit"; // EOF, ^C, ^D
  const k = raw.trim().toLowerCase()[0] ?? "";
  return k === "a" ? "apply" : k === "s" ? "skip" : k === "p" ? "policy" : k === "?" || k === "h" ? "help" : k === "q" ? "quit" : "other";
}

/**
 * The arbiter's words for a write refused because a change to policy.yaml
 * waits in Approvals and this write cannot be made to it as well
 * (arbiter/policy/policy-document-store.ts `StalePolicyError` with `held`;
 * policy-surface.md §8.4.6), the same words the dashboard's routes read
 * (dashboard/src/server/policy-proposal-routes.ts). On the wire the refusal
 * is `stale` either way; only its words tell it from a file that moved.
 * Pinned to the arbiter's message by tests/stack/policy-held-suggest-undo.test.ts.
 */
export const HELD_EDIT_REFUSAL_RE = /waits for a human in Approvals/;

/** Is this refusal the held-edit one (above), not a file that moved? Pure. */
export function refusedByHeldEdit(r: ApplySuggestionWire): boolean {
  return !r.applied && r.refused === "stale" && r.problems.some((p) => HELD_EDIT_REFUSAL_RE.test(p));
}

/** What to do about a suggestion a held edit of policy.yaml keeps out
 *  (first-session tour 17): running this again is refused the same way
 *  until the person answers the held change, on its card on the dashboard's
 *  Approvals page; nothing in the terminal answers it. */
export const HELD_EDIT_LINE =
  "Not applied yet: policy.yaml has a change made on disk that waits for your OK on the dashboard's Approvals page, " +
  "and this suggestion names something that change removes or changes, so the two cannot both be made. " +
  "Answer that change there first (Allow or Not now; `mandu dashboard` opens it), then run `mandu policy suggest` again. " +
  "This suggestion stays waiting.";

/** A refusal in plain words. Pure. `held`: refused only until the change
 *  waiting in Approvals is answered (`refusedByHeldEdit`). */
export function applyOutcome(r: ApplySuggestionWire): { applied: boolean; failed: boolean; line: string; held?: true } {
  if (r.applied) return { applied: true, failed: false, line: `Applied (change ${clean(r.changeId)}; undo it in the dashboard, under Rule changes in Approvals).` };
  const why = r.problems.map(clean).join("; ");
  if (refusedByHeldEdit(r)) return { applied: false, failed: true, line: HELD_EDIT_LINE, held: true };
  switch (r.refused) {
    case "covered": return { applied: false, failed: false, line: "Already covered by your policy; the suggestion is closed." };
    case "unsupported": return { applied: false, failed: true, line: `Not applied: this Mandu cannot apply it yet (${why}). It stays waiting.` };
    case "stale": return { applied: false, failed: true, line: `Not applied: policy.yaml changed on disk meanwhile (${why}). Run this again.` };
    case "relaxes": return { applied: false, failed: true, line: `Not applied: your policy changed since the scan and this would now loosen it (${why}). Review it in the dashboard.` };
    default: return { applied: false, failed: true, line: `Not applied (${r.refused}): ${why}` };
  }
}

/** Why a sensitivity-label suggestion below no-model (`humanOnly`, §14.1) is
 *  not applied from here: its lock could override a stronger protection, so
 *  only a person approves it, on the dashboard's channel. */
export const HUMAN_ONLY_LINE = "only you can approve this level, in the dashboard (Rules › Keys Mandu found); skip it here";

/** Why a suggestion cannot be applied from here, or null. Pure. */
export function whyNotApplicable(v: SuggestionViewWire): string | null {
  if (v.humanOnly === true) return HUMAN_ONLY_LINE;
  if (v.applicable) return null;
  const ops = [...new Set(v.edits.map((e) => e.op))].filter((op) => op !== "lock-path");
  return `this Mandu cannot apply ${ops.length > 0 ? ops.join(", ") : "it"} yet (hiding an old version of a file needs a newer Mandu); skip it for now`;
}

// ── the command ──────────────────────────────────────────────────────────────

export interface PolicySuggestDeps {
  /** The resident arbiter (secrets axis ON), else a throwaway (doctor-secrets.ts). */
  arbiter: (env: Env, layout: Layout) => Promise<DryRunArbiter>;
  suggest: (sock: string, roots: string[], home: string, waitMs: number, timeoutMs: number, opts?: SuggestOptsWire) => Promise<SuggestPolicyWire>;
  apply: (sock: string, suggestionId: string) => Promise<ApplySuggestionWire>;
  /** `modelSuggestPreview` (§14.2). Default: the production call. */
  preview?: (sock: string, roots: string[], home: string, opts: { endpoint?: string; includeHome?: boolean; tier?: "names" | "contents" }) => Promise<ModelPreviewWire>;
  /** `modelSuggest` (§14.2), answering by `waitMs` at the latest. Default:
   *  the production call. */
  send?: (sock: string, digest: string, waitMs: number) => Promise<ModelRunWire>;
  cwd: () => string;
  isTTY: () => boolean;
  /** One key press ("" at end of input). */
  readKey: () => Promise<string>;
  /** One typed line ("" at end of input). */
  readLine: (prompt: string) => Promise<string>;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  out?: (s: string) => void;
  err?: (s: string) => void;
  /** The host a launch would enforce the rules on (default: this
   *  process's): on darwin the review says a history rule holds on Linux
   *  only. A test knob. */
  platform?: NodeJS.Platform;
}

/** Read one key from a terminal in raw mode (echoed by the caller). */
async function rawKey(): Promise<string> {
  const stdin = process.stdin;
  return new Promise<string>((resolveKey) => {
    const wasRaw = stdin.isRaw === true;
    const done = (s: string): void => {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      try { stdin.setRawMode?.(wasRaw); } catch { /* not a TTY any more */ }
      stdin.pause();
      resolveKey(s);
    };
    const onData = (d: Buffer | string): void => done(typeof d === "string" ? d : d.toString("utf8"));
    const onEnd = (): void => done("");
    try { stdin.setRawMode?.(true); } catch { /* line mode: the key arrives with Enter */ }
    stdin.on("data", onData);
    stdin.once("end", onEnd);
    stdin.resume();
  });
}

/** The production `modelSuggestPreview` call: the walk has the workspace
 *  scan's deadline (plus a margin); the default helper's description spawns
 *  the classifier once. */
export function modelPreviewCall(sock: string, roots: string[], home: string, opts: { endpoint?: string; includeHome?: boolean; tier?: "names" | "contents" }): Promise<ModelPreviewWire> {
  return ndjsonCall<ModelPreviewWire>(sock, "modelSuggestPreview", {
    tier: opts.tier ?? "names", roots, home,
    ...(opts.endpoint !== undefined ? { endpoint: opts.endpoint } : {}),
    ...(opts.includeHome === true ? { includeHome: true } : {}),
  }, 90_000);
}

/** The production `modelSuggest` call (one poll of at most `waitMs`). */
export function modelSendCall(sock: string, digest: string, waitMs: number): Promise<ModelRunWire> {
  return ndjsonCall<ModelRunWire>(sock, "modelSuggest", { digest, waitMs }, waitMs + 30_000);
}

export function realPolicySuggestDeps(): PolicySuggestDeps {
  return {
    arbiter: realDoctorSecretsDeps().arbiter,
    // No `sources`: every scan runs (the history, the workspace and the
    // sensitivity labels, §13.5, §14.1).
    suggest: (sock, roots, home, waitMs, timeoutMs, opts) =>
      ndjsonCall<SuggestPolicyWire>(sock, "suggestPolicy", {
        roots, home, waitMs,
        ...(opts?.includeHome === true ? { includeHome: true } : {}),
        ...(opts?.countLabels === true ? { countLabels: true } : {}),
        ...(opts?.answerFromEarlier === true ? { answerFromEarlier: true } : {}),
      }, timeoutMs),
    apply: (sock, id) => ndjsonCall<ApplySuggestionWire>(sock, "applySuggestion", { suggestionId: id }, 15_000),
    preview: modelPreviewCall,
    send: modelSendCall,
    cwd: () => process.cwd(),
    isTTY: () => process.stdin.isTTY === true && process.stdout.isTTY === true,
    readKey: rawKey,
    readLine: async (q) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try { return await rl.question(q); } catch { return ""; } finally { rl.close(); }
    },
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
}

/** The directory is the repository root or inside it. */
function within(dir: string, repoRoot: string): boolean {
  return dir === repoRoot || dir.startsWith(repoRoot.endsWith("/") ? repoRoot : repoRoot + "/");
}

function realOr(p: string): string {
  try { return realpathSync(p); } catch { return p; }
}

/** The pending suggestions that belong to these roots (a scan still running
 *  answers every pending one): its repository holds a root or lies under
 *  one, or a path it locks lies under one (a workspace suggestion, §13.6,
 *  whose `repoRoot` is its scan root or a work tree below it). A sibling with
 *  a common prefix does not count. Pure over the paths given. */
export function suggestionsFor(list: SuggestionViewWire[], roots: string[]): SuggestionViewWire[] {
  const all = roots.flatMap((r) => [r, realOr(r)]);
  return list.filter((v) => v.status === "pending" && all.some((r) =>
    within(r, v.repoRoot) || within(v.repoRoot, r) || v.edits.some((e) => e.op === "lock-path" && within(e.path, r))));
}

/** How long the command waits for the two scans, which run in turn: the
 *  history scan's budget and margin (the doctor's, historyCallTimeoutMs) plus
 *  the workspace scan's deadline (MANDU_WORKSPACE_SCAN_TIMEOUT_S, 30 s by
 *  default, §13.1). Pure. */
export function suggestCallBudgetMs(env: Env): number {
  const s = Number(env["MANDU_WORKSPACE_SCAN_TIMEOUT_S"]);
  return historyCallTimeoutMs(env) + (Number.isFinite(s) && s > 0 ? s * 1000 : 30_000);
}

/** The arbiter's scan, waiting out one that is already running (the launch's
 *  background scan) until the deadline. */
async function scanWithin(deps: PolicySuggestDeps, sock: string, roots: string[], home: string, budgetMs: number, opts: SuggestOptsWire): Promise<SuggestPolicyWire> {
  const deadline = deps.now() + budgetMs;
  for (;;) {
    const left = Math.max(0, deadline - deps.now());
    const r = await deps.suggest(sock, roots, home, left, left + 10_000, opts);
    if (!r.running || deps.now() >= deadline) return r;
    await deps.sleep(Math.min(1000, Math.max(0, deadline - deps.now())));
  }
}

/** `mandu policy suggest …`: exit 0 done, 1 a failure (no arbiter, a scan
 *  or an apply failed, apply refused), 2 a usage error or a refusal before
 *  anything ran. */
export async function runPolicySuggest(
  rest: string[], env: Env, layout: Layout, deps: PolicySuggestDeps = realPolicySuggestDeps(),
): Promise<number> {
  const out = deps.out ?? ((s: string) => { process.stdout.write(s); });
  const err = deps.err ?? ((s: string) => { process.stderr.write(s); });
  const args = parsePolicySuggestArgs(rest);
  if (args.errors.length > 0) {
    for (const e of args.errors) err(`mandu policy suggest: ${e}\n`);
    err("run `mandu policy --help` for the options\n");
    return 2;
  }
  if (args.model !== null && !modelOffered(env)) {
    err(`mandu policy suggest: ${args.model === "contents" ? CONTENTS_NOT_OFFERED : MODEL_NOT_OFFERED}\n`);
    return 2;
  }
  const tty = deps.isTTY();
  const { mode, note, refuse } = suggestMode(args, tty);
  if (refuse !== null) { err(`mandu policy suggest: ${refuse}\n`); return 2; }
  const color = tty && !args.noColor && !args.json && (env["NO_COLOR"] ?? "") === "";
  const platform = deps.platform ?? process.platform;
  const home = env["HOME"] ?? homedir();
  const cwd = deps.cwd();
  const roots = (args.roots.length > 0 ? args.roots : [cwd]).map((r) => (r === "~" ? home : r.startsWith("~/") ? resolve(home, r.slice(2)) : isAbsolute(r) ? resolve(r) : resolve(cwd, r)));

  let arb: DryRunArbiter;
  try {
    arb = await deps.arbiter(env, layout);
  } catch (e) {
    err(`mandu policy suggest: no Mandu service could run the scan (${(e as Error).message})\n`);
    return 1;
  }
  try {
    const canApply = arb.kind === "resident";
    const whyNoApply = canApply
      ? null
      : arb.axisOn === false
        ? "the running Mandu service has secret protection off (see `mandu mode`), so a temporary one scanned; its suggestions are not kept, and nothing can be applied from here"
        : "no Mandu service is running, so a temporary one scanned; its suggestions are not kept, and nothing can be applied from here. Start Mandu (run your agent under it, e.g. `mandu claude`) and run this again to apply";
    if (mode === "apply-all" && !canApply) {
      err(`mandu policy suggest: --apply-all refused: ${whyNoApply}\n`);
      return 1;
    }
    if (mode !== "json") {
      if (note !== null) out(`mandu policy suggest: ${note}\n`);
      out(`Scanning the git history and the files of ${roots.map((p) => clean(tilde(p, home))).join(", ")}${args.home ? ", and your home folder's configuration files" : ""} …\n`);
    }
    let r: SuggestPolicyWire;
    try {
      // An explicit scan: count the Office files' labels even with no
      // mapping, so the header can say how many wait to be mapped (§14.1).
      r = await scanWithin(deps, arb.sock, roots, home, suggestCallBudgetMs(env), { ...(args.home ? { includeHome: true } : {}), countLabels: true });
    } catch (e) {
      const m = (e as Error).message;
      err(`mandu policy suggest: the scan failed (${clean(m)})${/unknown op/i.test(m) ? "; the running Mandu service is older than this command: restart it (`mandu stop`, then launch again)" : ""}\n`);
      return 1;
    }
    if (!r.axis) {
      err("mandu policy suggest: the Mandu service that answered has secret protection off; nothing was scanned (see `mandu mode`)\n");
      return 1;
    }
    // History-only secrets first (nothing hides them today, plan 14 §4), then
    // oldest first (the arbiter lists newest first).
    const order = (a: SuggestionViewWire, b: SuggestionViewWire): number =>
      Number(b.historyOnly) - Number(a.historyOnly) || a.createdAt - b.createdAt || a.id.localeCompare(b.id);
    let list = (r.running ? suggestionsFor(r.suggestions, args.home ? [...roots, home] : roots) : r.suggestions.filter((v) => v.status === "pending"))
      .slice().sort(order);

    if (mode !== "json") out(renderScanHeader(r, roots, home, platform));
    // The model (§14.5, §14.11): after the scans, on consent.
    let model: ModelStepResult | null = null;
    if (args.model !== null) {
      model = await modelStep(deps, arb, { roots, home, args, mode, tty, out, err });
      const seen = new Set(list.map((v) => v.id));
      list = [...list, ...(model.run?.suggestions ?? []).filter((v) => v.status === "pending" && !seen.has(v.id))].sort(order);
    }

    if (mode === "json") {
      out(jsonText({
        arbiter: arb.kind, canApply, running: r.running, roots, includeHome: args.home,
        suggestions: list, covered: r.covered, counts: r.counts, scan: r.scan, workspaceScan: r.workspaceScan ?? null,
        ...(model !== null ? { model: { preview: model.preview, run: model.run, note: model.note } } : {}),
      }) + "\n");
      return model?.failed ? 1 : 0;
    }
    if (model?.failed) return 1;

    if (list.length === 0) {
      out(r.running ? "Nothing is waiting for review yet.\n" : "Nothing to suggest: your policy covers every key the scan found.\n");
      return 0;
    }
    out(`\n${plural(list.length, "suggestion waits", "suggestions wait")} for you. Nothing changes unless you apply it.\n`);
    if (whyNoApply !== null) out(`Note: ${whyNoApply}.\n`);
    out(`${DISMISS_NOTE}\n\n`);

    const opts = { home, color, platform };
    if (mode === "review") {
      list.forEach((v, i) => {
        out(renderSuggestion(v, i + 1, list.length, opts));
        const why = whyNotApplicable(v);
        if (why !== null) out(`${INDENT}${why}\n`);
        out("\n");
      });
      out(`Nothing was applied${mode === "review" && args.dryRun ? " (--dry-run)" : ""}. Run \`mandu policy suggest\` in a terminal to apply, or open Keys Mandu found in the dashboard.\n`);
      return 0;
    }

    let applied = 0, skipped = 0, failed = 0, held = 0;
    if (mode === "apply-all") {
      list.forEach((v, i) => { out(renderSuggestion(v, i + 1, list.length, opts)); const why = whyNotApplicable(v); if (why !== null) out(`${INDENT}${why}\n`); out("\n"); });
      const todo = list.filter((v) => whyNotApplicable(v) === null);
      if (todo.length === 0) { out("None of these can be applied by this Mandu yet; nothing applied.\n"); return 0; }
      const typed = (await deps.readLine(`Apply ${plural(todo.length, "suggestion", "suggestions")} to your policy? Type "apply" to confirm: `)).trim().toLowerCase();
      if (typed !== "apply") { out("Not confirmed; nothing applied.\n"); return 0; }
      for (const v of todo) {
        const res = await applyOne(deps, arb.sock, v, out, platform);
        if (res === "applied") applied++; else if (res === "failed") failed++; else if (res === "held") { failed++; held++; }
      }
      skipped = list.length - todo.length;
    } else {
      let quit = false;
      for (let i = 0; i < list.length && !quit; i++) {
        const v = list[i]!;
        out(renderSuggestion(v, i + 1, list.length, opts));
        const why = whyNoApply !== null ? null : whyNotApplicable(v);
        if (why !== null) out(`${INDENT}${why}\n`);
        const allowApply = whyNoApply === null && why === null;
        for (;;) {
          out(promptLine(allowApply));
          const raw = await deps.readKey();
          const key = readReviewKey(raw);
          out(`${key === "quit" ? "q" : clean(raw.trim()).slice(0, 1)}\n`);
          if (key === "help") { out(KEY_HELP); continue; }
          if (key === "policy") {
            out(`${INDENT}applying it adds to policy.yaml:\n${policyYamlLines(v).map((l) => `${INDENT}  ${l}`).join("\n")}\n`);
            continue;
          }
          if (key === "skip") { skipped++; break; }
          if (key === "quit") { quit = true; break; }
          if (key === "apply" && allowApply) {
            const res = await applyOne(deps, arb.sock, v, out, platform);
            if (res === "applied") applied++; else if (res === "failed") failed++; else if (res === "held") { failed++; held++; }
            break;
          }
          out(`${INDENT}press ${allowApply ? "a, " : ""}s, p, q or ?\n`);
        }
        out("\n");
      }
    }
    out(closingLine({ total: list.length, applied, skipped, failed, held }));
    return failed > 0 ? 1 : 0;
  } finally {
    await arb.stop();
  }
}

/** What the model step did (§14.5). */
export interface ModelStepResult {
  preview: ModelPreviewWire | null;
  run: ModelRunWire | null;
  /** Why nothing was sent, or null when it was. */
  note: string | null;
  /** A refusal or failure: the command exits 1. */
  failed: boolean;
}

/** How long the command waits for a model run (the arbiter stops one at 5
 *  minutes, plus its margin). */
export const MODEL_RUN_BUDGET_MS = 6 * 60_000;
/** A contents run (§14.11): the arbiter stops one at 30 minutes. */
export const CONTENTS_RUN_BUDGET_MS = 31 * 60_000;

/**
 * The model step (§14.2, §14.5): the preview the arbiter built and keeps,
 * then consent (a terminal's [y], or `--yes-send` repeating the preview's
 * digest), then the send, polled until the run ends. Nothing is sent on
 * `--dry-run`, on [N], without a terminal and without `--yes-send`, or when
 * `--yes-send` names another digest.
 */
async function modelStep(
  deps: PolicySuggestDeps,
  arb: DryRunArbiter,
  o: { roots: string[]; home: string; args: PolicySuggestArgs; mode: SuggestMode; tty: boolean; out: (s: string) => void; err: (s: string) => void },
): Promise<ModelStepResult> {
  const text = o.mode !== "json";
  const say = (s: string): void => { if (text) o.out(s); };
  const tier = o.args.model === "contents" ? "contents" as const : "names" as const;
  const what = tier === "contents" ? "files" : "names";
  if (arb.kind !== "resident") {
    const note = `the ${tier === "contents" ? "contents" : "names-only"} model runs only with the running Mandu service (its suggestions must be kept); start Mandu and run this again`;
    o.err(`mandu policy suggest: ${note}\n`);
    return { preview: null, run: null, note, failed: true };
  }
  let preview: ModelPreviewWire;
  try {
    preview = await (deps.preview ?? modelPreviewCall)(arb.sock, o.roots, o.home, {
      ...(o.args.endpoint !== null ? { endpoint: o.args.endpoint } : {}),
      ...(o.args.home ? { includeHome: true } : {}),
      ...(tier === "contents" ? { tier } : {}),
    });
  } catch (e) {
    const m = clean((e as Error).message);
    o.err(`mandu policy suggest: the model step did not start (${m})${/unknown op/i.test(m) ? "; the running Mandu service is older than this command: restart it (`mandu stop`, then launch again)" : ""}\n`);
    return { preview: null, run: null, note: m, failed: true };
  }
  if (preview.items === 0 || preview.digest === "") {
    const note = tier === "contents"
      ? "no document to send (every document the scan found is protected, holds something like a key, or was left out)"
      : "no file or folder name to send (everything the scan listed is protected or was left out)";
    say(`\n${note[0]!.toUpperCase()}${note.slice(1)}.\n`);
    return { preview, run: null, note, failed: false };
  }
  say(`\n${modelPreviewLine(preview)}\n`);
  for (const l of modelPreviewNotes(preview)) say(`  ${l}\n`);
  let send = false;
  if (o.args.dryRun) {
    const note = `--dry-run: nothing was sent. To send exactly these ${what} without a terminal: mandu policy suggest --model ${tier}${o.args.home ? " --home" : ""}${o.args.endpoint !== null ? ` --endpoint ${o.args.endpoint}` : ""} --yes-send ${preview.digest}`;
    say(`${note}\n`);
    return { preview, run: null, note, failed: false };
  }
  if (o.args.yesSend !== null) {
    if (o.args.yesSend !== preview.digest) {
      const note = `the ${tier === "contents" ? "files" : "names"} to send changed since that preview (another digest); nothing was sent: look again with --dry-run --json`;
      o.err(`mandu policy suggest: ${note}\n`);
      return { preview, run: null, note, failed: true };
    }
    send = true;
  } else if (!o.tty || o.mode === "json") {
    const note = `no terminal to ask on: nothing was sent. Look at the ${what} (--dry-run --json), then repeat with --yes-send ${preview.digest}`;
    say(`${note}\n`);
    return { preview, run: null, note, failed: false };
  } else {
    for (;;) {
      o.out(`  ${tier === "contents" ? CONSENT_PROMPT_FILES : CONSENT_PROMPT}`);
      const raw = await deps.readKey();
      const k = readConsentKey(raw);
      o.out(`${k === "view" ? "v" : k === "yes" ? "y" : "n"}\n`);
      if (k === "view") { o.out(tier === "contents" ? renderModelFiles(preview, o.home) : renderModelNames(preview, o.home)); continue; }
      send = k === "yes";
      break;
    }
    if (!send) {
      const note = "nothing was sent";
      o.out("  Nothing was sent.\n");
      return { preview, run: null, note, failed: false };
    }
  }
  say(`  Sending to ${clean(preview.destination.name)} …\n`);
  const deadline = deps.now() + (tier === "contents" ? CONTENTS_RUN_BUDGET_MS : MODEL_RUN_BUDGET_MS);
  let run: ModelRunWire;
  try {
    for (;;) {
      run = await (deps.send ?? modelSendCall)(arb.sock, preview.digest, 2000);
      if (!run.running || deps.now() >= deadline) break;
    }

  } catch (e) {
    const m = clean((e as Error).message);
    o.err(`mandu policy suggest: the model run failed (${m})\n`);
    return { preview, run: null, note: m, failed: true };
  }
  say(`  ${modelRunLine(run, tier)}\n`);
  return { preview, run, note: null, failed: false };
}

/** The review's last line. `held` of the `failed` were refused only until
 *  the change to policy.yaml waiting in Approvals is answered: for those,
 *  "run this again" alone is refused the same way, so the line says where
 *  that change is answered (first-session tour 17). Pure. */
export function closingLine(k: { total: number; applied: number; skipped: number; failed: number; held: number }): string {
  const left = k.total - k.applied;
  const head = `Applied ${k.applied}, skipped ${k.skipped}${k.failed > 0 ? `, ${k.failed} not applied` : ""}. `;
  if (left <= 0) return `${head}Nothing is left waiting.\n`;
  const stay = plural(left, "suggestion stays", "suggestions stay");
  if (k.held === 0) return `${head}${stay} waiting: run this again, or open Keys Mandu found in the dashboard.\n`;
  return `${head}${stay} waiting; ${k.held === 1 ? "one waits" : `${k.held} wait`} on the change to policy.yaml on the dashboard's Approvals page: ` +
    "answer that change there (`mandu dashboard`), then run `mandu policy suggest` again.\n";
}

async function applyOne(
  deps: PolicySuggestDeps, sock: string, v: SuggestionViewWire, out: (s: string) => void, platform: string = "linux",
): Promise<"applied" | "covered" | "failed" | "held"> {
  try {
    const r = await deps.apply(sock, v.id);
    const o = applyOutcome(r);
    // macOS: an applied history rule is enforced by Linux launches only.
    out(`${INDENT}${o.line}${o.applied && platform === "darwin" && hidesHistory(v) ? ` ${MACOS_APPLIED_NOTE}` : ""}\n`);
    return o.applied ? "applied" : o.held ? "held" : o.failed ? "failed" : "covered";
  } catch (e) {
    out(`${INDENT}Not applied: ${clean((e as Error).message)}\n`);
    return "failed";
  }
}

/** `mandu policy <verb>`: `suggest`, and `classifier-pack` (plan 15 §13.5
 *  item 15: the reference classifier's pack, from the copy this install
 *  ships). */
export async function runPolicy(rest: string[], env: Env, layout: Layout, deps?: PolicySuggestDeps): Promise<number> {
  const [verb, ...more] = rest;
  if (verb === "suggest") return runPolicySuggest(more, env, layout, deps);
  if (verb === "classifier-pack") return runClassifierPack(more, layout);
  const err = deps?.err ?? ((s: string) => { process.stderr.write(s); });
  err(verb === undefined
    ? "mandu policy: which one? `mandu policy suggest` or `mandu policy classifier-pack` (see `mandu policy --help`)\n"
    : `mandu policy: unknown command '${clean(verb)}' (see \`mandu policy --help\`)\n`);
  return 2;
}

// ── the launch-time notice (§5.5) ────────────────────────────────────────────

/** Default budget the launch gives the scan before it answers. */
export const LAUNCH_SUGGEST_WAIT_MS = 1500;
/** On top of the budget, for the reply to arrive (a wedged arbiter). */
export const LAUNCH_SUGGEST_MARGIN_MS = 500;

/** Whether the launch asks, and with what budget. Pure.
 *  MANDU_SUGGEST_AT_LAUNCH=0 turns it off; MANDU_SUGGEST_WAIT_MS sets the
 *  budget (0..30000 ms; anything else is the default). */
export function launchSuggestConfig(env: Env): { enabled: boolean; waitMs: number } {
  const off = ["0", "false", "no", "off"].includes((env["MANDU_SUGGEST_AT_LAUNCH"] ?? "").toLowerCase());
  const raw = env["MANDU_SUGGEST_WAIT_MS"];
  const n = raw !== undefined && raw !== "" ? Number(raw) : NaN;
  const waitMs = Number.isFinite(n) && n >= 0 && n <= 30_000 ? Math.floor(n) : LAUNCH_SUGGEST_WAIT_MS;
  return { enabled: !off, waitMs };
}

/** What the line says after its advice when its count comes from an earlier
 *  scan's result (§5.5): the scan of this launch still runs. The compact
 *  display drops it with the advice (launch-banner.ts compactNotice). */
export const EARLIER_SCAN_NOTE = " (from the last finished scan; a new one is running)";

/** Is this answer an earlier scan's result (§5.5): the scan still runs and
 *  the arbiter says one of these roots finished before? Pure. */
export function fromEarlierScan(r: SuggestPolicyWire): boolean {
  return r.running && typeof r.lastScanAt === "number";
}

/** The one line, or null when nothing in this project waits: the pending
 *  suggestions whose repository holds the cwd or whose paths lie under it,
 *  from either scan (§13.6). An earlier scan's result says so at the end
 *  (EARLIER_SCAN_NOTE). Pure over the answer. */
export function launchSuggestionNotice(r: SuggestPolicyWire | null, cwd: string): string | null {
  if (r === null || !r.axis) return null;
  const mine = suggestionsFor(r.suggestions, [cwd]);
  const n = mine.length;
  if (n === 0) return null;
  // A labelled Office document (§14.1) is not a key: it is named as what it is.
  const docs = mine.filter((v) => v.source === "sensitivity-label").length;
  // A model's suggestion (§14.10, §14.11) is not a key either: a file or a
  // folder your model called sensitive.
  const flagged = mine.filter((v) => v.source === "model-names" || v.source === "model-contents").length;
  const keys = n - docs - flagged;
  const what = [
    ...(keys > 0 ? [plural(keys, "possible key", "possible keys")] : []),
    ...(docs > 0 ? [plural(docs, "labelled document", "labelled documents")] : []),
    ...(flagged > 0 ? [plural(flagged, "file your model called sensitive", "files your model called sensitive")] : []),
  ].join(" and ");
  return `mandu: ${what} in this project ${n === 1 ? "is" : "are"} not protected: ` +
    "run `mandu policy suggest` or open Keys Mandu found in the dashboard" + (fromEarlierScan(r) ? EARLIER_SCAN_NOTE : "");
}

export interface LaunchSuggestDeps {
  suggest: (sock: string, roots: string[], home: string, waitMs: number, timeoutMs: number, opts?: SuggestOptsWire) => Promise<SuggestPolicyWire>;
  /** Debug only (launch.log): never printed in the compact display. */
  debug?: (m: string) => void;
}

/**
 * Start the launch's advisory scan (§5.5). Never rejects and never takes
 * longer than the budget plus a margin: the arbiter answers when the budget
 * ends (`running: true`) and finishes the scan in the background; a wedged or
 * older arbiter is cut off by the call's own deadline. The call asks
 * `answerFromEarlier`: when a scan of this workspace already finished, the
 * arbiter answers at once from that result and runs this one in the
 * background, so only a workspace's first launch (per arbiter run) waits.
 * Nothing of the scan stays with the launcher after the answer (the arbiter
 * owns it), and once this settles it reports nothing more, so it can never
 * write into the agent's terminal. The caller starts it early and awaits it
 * just before the banner, so it overlaps the rest of the launch. Resolves to
 * the notice line or null.
 */
export function startLaunchSuggest(
  o: { sock: string; cwd: string; home: string; env: Env },
  deps: LaunchSuggestDeps = { suggest: realPolicySuggestDeps().suggest },
): Promise<string | null> {
  const cfg = launchSuggestConfig(o.env);
  if (!cfg.enabled) return Promise.resolve(null);
  // A late failure (the call's own deadline, after the cap settled) is not
  // reported: the banner is out and the agent may own the terminal.
  let settled = false;
  const debug = (m: string): void => { if (!settled) deps.debug?.(m); };
  let p: Promise<SuggestPolicyWire>;
  try {
    p = deps.suggest(o.sock, [o.cwd], o.home, cfg.waitMs, cfg.waitMs + LAUNCH_SUGGEST_MARGIN_MS, { answerFromEarlier: true });
  } catch (e) {
    debug(`mandu: policy suggestions not checked (${(e as Error).message})`);
    return Promise.resolve(null);
  }
  // The call carries its own deadline; this one holds even for a caller
  // whose `suggest` has none.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const cap = new Promise<null>((res) => {
    // Not unref'd: it is bounded, cleared on the answer, and an awaited
    // promise must not be left with nothing to settle it.
    timer = setTimeout(() => { debug("mandu: policy suggestions not checked (no answer within the budget)"); res(null); }, cfg.waitMs + LAUNCH_SUGGEST_MARGIN_MS);
  });
  const answer = p.then(
    (r) => {
      if (fromEarlierScan(r)) debug("mandu: policy suggestions from the last finished scan; this launch's scan runs in the background");
      return launchSuggestionNotice(r, o.cwd);
    },
    (e: Error) => { debug(`mandu: policy suggestions not checked (${e.message})`); return null; },
  );
  return Promise.race([answer, cap]).finally(() => { settled = true; if (timer !== undefined) clearTimeout(timer); });
}
