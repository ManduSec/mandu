/**
 * policy-suggestion-ops — the arbiter side of policy suggestions
 * (docs/design/confidentiality/confidentiality-plan-14-policy-suggestions.md §5.1, §5.2).
 * Mandu-new.
 *
 * The server delegates `suggestPolicy` (after its scan), `policySuggestions`,
 * `applySuggestion`, `dismissSuggestion` and a `resolvePolicyProposal` on a
 * suggestion here. The CHANNEL rule is the server's (`ADMIN_ONLY_OPS` holds
 * `dismissSuggestion`); the rules here:
 *
 *   - FILING. Only the arbiter files a suggestion, from its own scan, as
 *     `mandu:scan` (SCAN_REQUESTER). A pending or dismissed finding key is
 *     never filed twice, nor a suggestion whose every locked subject a
 *     pending or dismissed suggestion of either source (the git history, the
 *     workspace: plan 14 §13.4) already locks; at most
 *     SUGGESTION_CAP_PER_REPO are pending per repository, both sources
 *     counted, the rest counted. Every one passed the generator's
 *     tightening check (policy-suggestions.ts).
 *   - SUPERSEDING. A pending suggestion the law now covers (the person
 *     labelled the path another way, a folder above it included) is closed
 *     `superseded` on every scan, every read and every apply.
 *   - APPLYING. On any channel, a suggestion applies only as a PURE
 *     tightening of the law in force, re-evaluated at apply time (the law may
 *     have moved since the scan); `via: "agent-tighten"` on the data plane
 *     (the agent's channel: who pressed apply there is not attested),
 *     `via: "tighten"` on the admin channel's applySuggestion, `via:
 *     "proposal"` when a human approves it on the admin channel. It closes
 *     `approved` with the change id. Anything else is refused and it stays
 *     pending, except "the law already says this", which closes it.
 *   - DISMISSING ("Not a secret") denies it, which is what keeps its finding
 *     key from being filed again. Admin only: it withholds protection.
 *   - SENSITIVITY LABELS (plan 14 §14.1, §14.9): the workspace walk's
 *     labelled Office files are filed through the mapping in force, after
 *     the other two sources. A stricter single-path lock REPLACES a weaker
 *     pending one for the same file (closed `superseded` by it). A label
 *     lock below no-model is `humanOnly`: refused on the data plane, applied
 *     by a person (`via: "proposal"`) only as the one new label on its own
 *     file and never over a protection in force (`protectedNow`).
 *   - THE MODEL (plan 14 §14.4, §14.10, §14.11): what a model run keeps is
 *     filed after the scans, with the same dedup and the shared cap. A
 *     contents-model answer below no-model is the same `humanOnly` lock on
 *     its own file as a label's and takes the same apply path.
 *
 * Every write goes through `PolicyDocumentStore.applyGuarded`, like every
 * other write of the policy surface (policy-agent-ops.ts): a hand edit landed
 * in the poll window is refused as stale, and one held in Approvals gets the
 * same change made to it (policy-surface.md §8.4.6).
 */
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { getCurrentPolicy } from "../policy/compiled-policy.js";
import { StalePolicyError, type PolicyDocumentStore } from "../policy/policy-document-store.js";
import { POLICY_EDIT_OPS, canonicalJson, diffItems, evaluateEdits, type PolicyEdit } from "../policy/policy-edit.js";
import { SCAN_REQUESTER, suggestionSubject, type PolicyProposal, type PolicyProposalStore, type ProposalStatus } from "../policy/policy-proposals.js";
import { editCovered, judgeHumanLabelLock, suggestEdits, suggestLabelEdits, suggestWorkspaceEdits, type LockPathEdit, type Suggestion, type SuggestLaw, type SuggestionEdit } from "../policy/policy-suggestions.js";
import { labelLevelRank, type LabelMappingEntry } from "../policy/sensitivity-labels.js";
import type { PathLabel } from "../policy/path-labels.js";
import type { SecretHistoryScan } from "../policy/secret-history-scan.js";
import type { SecretWorkspaceScan, SecretWorkspaceScanSummary } from "../policy/secret-workspace-scan.js";
import { OpError, layerEdits, proposalWire } from "./policy-agent-ops.js";
import type {
  ApplySuggestionResult,
  DismissSuggestionResult,
  PolicySuggestionsResult,
  ResolvePolicyProposalResult,
  SuggestionView,
  SuggestPolicyCounts,
  SuggestPolicyResult,
} from "./protocol.js";

/** Plan 14 §5.1: pending suggestions per repository; the rest are counted. */
export const SUGGESTION_CAP_PER_REPO = 20;

/** What a suggestion event says (best-effort, no values). */
export interface SuggestionEvent {
  action: "filed" | "applied" | "dismissed" | "superseded";
  ids: string[];
}

export interface PolicySuggestionOpsDeps {
  docs: PolicyDocumentStore;
  proposals: PolicyProposalStore;
  /** Observability (the server's admin stream); never on the decision path. */
  emit?: (e: SuggestionEvent) => void;
  exists?: (absPath: string) => boolean;
  /** Does the catalog or a label protect this absolute path now (the walk's
   *  coverage check)? A `humanOnly` label suggestion is closed as covered
   *  instead of applied when it does: its lock below no-model would
   *  override that protection. Unset: nothing is protected. */
  protectedNow?: (absPath: string) => boolean;
  /** The path labels in force: policy.yaml's `paths:` AND mandu.db's label
   *  rows (a dashboard act, a label on a path that no longer exists), the
   *  set the label lookup and the secret twins use. Every coverage check
   *  (filing, superseding, applying) reads it, so a path labelled only in
   *  mandu.db is never suggested again. Unset: policy.yaml's alone. */
  pathLabels?: () => ReadonlyMap<string, PathLabel>;
  now?: () => number;
}

function hashOf(v: unknown): string {
  return createHash("sha256").update(canonicalJson(v)).digest("hex").slice(0, 32);
}

function knownOps(edits: readonly { op: string }[]): boolean {
  return edits.every((e) => (POLICY_EDIT_OPS as readonly string[]).includes(e.op));
}

/** The workspace scan as `suggestPolicy` answers it: everything but the
 *  findings (they became suggestions). */
export function workspaceSummary(s: SecretWorkspaceScan): SecretWorkspaceScanSummary {
  return { roots: s.roots, counts: s.counts, capped: s.capped, limits: s.limits, ms: s.ms, ...(s.labels !== undefined ? { labels: s.labels } : {}) };
}

/** The one lock a suggestion makes, when it makes exactly one `lock-path`
 *  (the only shape a stricter suggestion may replace). */
function singleLock(edits: readonly { op: string }[]): { path: string; level: string } | null {
  if (edits.length !== 1) return null;
  const e = edits[0] as { op: string; path?: unknown; level?: unknown };
  return e.op === "lock-path" && typeof e.path === "string" && typeof e.level === "string" ? { path: e.path, level: e.level } : null;
}

/** Does `edits` lock the same single path as every one of `olds`, strictly
 *  higher (plan 14 §14.1: "the stricter level winning when both are
 *  pending")? */
function stricterThanAll(edits: readonly { op: string }[], olds: readonly PolicyProposal[]): boolean {
  const mine = singleLock(edits);
  if (mine === null || olds.length === 0) return false;
  return olds.every((o) => {
    const theirs = singleLock(o.edits);
    return theirs !== null && theirs.path === mine.path && labelLevelRank(theirs.level) < labelLevelRank(mine.level);
  });
}

export function emptyCounts(): SuggestPolicyCounts {
  return { findings: 0, suggested: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, covered: 0, dropped: 0, superseded: 0 };
}

/** A suggestion row as the review shows it. */
export function suggestionView(p: PolicyProposal): SuggestionView {
  const s = p.suggestion;
  const edits = p.edits as unknown as SuggestionEdit[];
  return {
    id: p.id,
    kind: "suggestion",
    status: p.status,
    requestedBy: p.requestedBy,
    findingKey: p.findingKey ?? "",
    source: s?.source ?? "git-history",
    repoRoot: s?.repoRoot ?? "",
    edits: [...edits],
    sentence: s?.sentence ?? "",
    evidence: s?.evidence ?? { paths: [], blobs: [], findings: [], historyOnly: false },
    impact: s?.impact ?? { historicalVersions: 0, workingTreeChanges: false, files: [] },
    historyOnly: s?.historyOnly ?? false,
    rotate: s?.rotate ?? true,
    humanOnly: s?.humanOnly === true,
    ...(s?.model ? { model: s.model } : {}),
    applicable: knownOps(edits),
    createdAt: p.createdAt,
    resolvedAt: p.resolvedAt,
    resolvedBy: p.resolvedBy,
    changeId: p.changeId,
    supersededBy: p.supersededBy,
  };
}

export class PolicySuggestionOps {
  private readonly now: () => number;

  constructor(private readonly deps: PolicySuggestionOpsDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  private emit(e: SuggestionEvent): void {
    if (e.ids.length === 0 || !this.deps.emit) return;
    try {
      this.deps.emit(e);
    } catch {
      /* best-effort */
    }
  }

  private law() {
    return { specId: getCurrentPolicy().specId, document: this.deps.docs.document };
  }

  /** The law with the path labels in force (policy.yaml + mandu.db). */
  private labelled(): SuggestLaw {
    return { ...this.law(), pathLabels: this.deps.pathLabels ? this.deps.pathLabels() : getCurrentPolicy().pathLabels };
  }

  /** The law covers the suggestion now: every lock's subject already has a
   *  label above public (policy-suggestions.ts `editCovered`), or its edits
   *  would change nothing. */
  private covered(p: PolicyProposal, law: SuggestLaw): boolean {
    const edits = p.edits as unknown as SuggestionEdit[];
    if (edits.length > 0 && edits.every((e) => editCovered(e, law))) return true;
    if (!knownOps(edits)) return false;
    const ev = evaluateEdits(law, p.edits, { now: this.now() });
    return ev.ok && ev.delta.tightenings.length === 0 && ev.delta.relaxations.length === 0;
  }

  /**
   * Close as `superseded` every pending suggestion the law in force now
   * covers (`covered`). Returns the closed ids.
   */
  refresh(): string[] {
    const closed: string[] = [];
    const labels = this.labelled();
    for (const p of this.deps.proposals.listProposals({ status: "pending", kind: "suggestion" })) {
      if (this.covered(p, labels)) {
        this.deps.proposals.resolveProposal(p.id, "superseded", SCAN_REQUESTER);
        closed.push(p.id);
      }
    }
    if (closed.length > 0) {
      this.deps.docs.log(`policy suggestions ${closed.join(", ")}: the law now covers them (superseded)`);
      this.emit({ action: "superseded", ids: closed });
    }
    return closed;
  }

  /** Plan 14 §4 + §5.1: generate from a finished history scan and file what
   *  is new (the history-only form of `fileFromScans`). */
  fileFromScan(scan: SecretHistoryScan, opts: { home?: string } = {}): SuggestPolicyResult {
    return this.fileFromScans({ history: scan }, opts);
  }

  /**
   * Plan 14 §4, §5.1, §13.4: generate from the finished scans (either may be
   * absent: its source was not asked for) and file what is new. History is
   * filed first. A suggestion is not filed when its finding key is pending
   * or dismissed, or when every subject it locks is already locked by a
   * pending suggestion of either source (`alreadyPending`) or a dismissed one
   * (`dismissed`): one suggestion per file across the two scans, and "Not a
   * secret" is about the file, whichever scan found it. The per-repository
   * cap counts both sources.
   */
  fileFromScans(
    scans: { history?: SecretHistoryScan | null; workspace?: SecretWorkspaceScan | null },
    opts: { home?: string; labelMapping?: readonly LabelMappingEntry[] } = {},
  ): SuggestPolicyResult {
    const history = scans.history ?? null;
    const workspace = scans.workspace ?? null;
    const labelFindings = workspace?.labelFindings ?? [];
    const counts = emptyCounts();
    counts.superseded = this.refresh().length;
    counts.findings = (history?.findings.length ?? 0) + (workspace?.findings.length ?? 0) + labelFindings.length;
    const law = this.law();
    const labelled = this.labelled();
    const now = this.now();
    const hist = history
      ? suggestEdits(history.findings, labelled, { exists: this.deps.exists ?? existsSync, ...(opts.home ? { home: opts.home } : {}), now })
      : { suggestions: [], covered: [], dropped: [] };
    const ws = workspace
      ? suggestWorkspaceEdits(workspace.findings, labelled, { ...(opts.home ? { home: opts.home } : {}), now })
      : { suggestions: [], covered: [], dropped: [] };
    // Plan 14 §14.1: the labelled Office files, through the mapping in force
    // (none: nothing is suggested; they were only counted).
    const lab = labelFindings.length > 0 && (opts.labelMapping?.length ?? 0) > 0
      ? suggestLabelEdits(labelFindings, opts.labelMapping!, labelled, { ...(opts.home ? { home: opts.home } : {}), now })
      : { suggestions: [], covered: [], dropped: [] };
    const gen = {
      suggestions: [...hist.suggestions, ...ws.suggestions, ...lab.suggestions],
      covered: [...hist.covered, ...ws.covered, ...lab.covered],
      dropped: [...hist.dropped, ...ws.dropped, ...lab.dropped],
    };
    counts.suggested = gen.suggestions.length;
    counts.covered = gen.covered.length;
    counts.dropped = gen.dropped.length;
    for (const d of gen.dropped) {
      this.deps.docs.log(`policy suggestion for ${d.repoRoot} dropped by the tightening check (${d.why})`);
    }
    const filed: string[] = [];
    const replaced: Array<{ old: string; by: string }> = [];
    const lawHash = hashOf(law.document ?? {});
    const locked = this.deps.proposals.suggestionSubjects();
    for (const s of gen.suggestions) {
      const subjects = s.edits.map(suggestionSubject).filter((x): x is string => x !== null);
      const replaces = this.admit(s, subjects, locked, counts);
      if (replaces === null) continue;
      for (const x of subjects) locked.pending.add(x);
      const known = s.edits.filter((e) => (POLICY_EDIT_OPS as readonly string[]).includes(e.op));
      const ev = known.length > 0 ? evaluateEdits(law, known, { now: this.now() }) : null;
      const { edits, findingKey, ...data } = s;
      const p = this.deps.proposals.fileSuggestion({
        edits: edits as unknown as PolicyEdit[],
        findingKey,
        suggestion: data,
        tightens: ev && ev.ok ? ev.delta.tightenings : [],
        editsHash: hashOf(edits),
        lawHash,
      });
      filed.push(p.id);
      for (const old of replaces) {
        this.deps.proposals.resolveProposal(old.id, "superseded", SCAN_REQUESTER, { supersededBy: p.id });
        replaced.push({ old: old.id, by: p.id });
      }
    }
    counts.filed = filed.length;
    counts.superseded += replaced.length;
    if (filed.length > 0) {
      this.deps.docs.log(`policy suggestions filed by Mandu's scan: ${filed.join(", ")} (they wait for the person)`);
      this.emit({ action: "filed", ids: filed });
    }
    if (replaced.length > 0) {
      this.deps.docs.log(`policy suggestions ${replaced.map((r) => `${r.old} (by ${r.by})`).join(", ")}: replaced by a stricter suggestion for the same file (superseded)`);
      this.emit({ action: "superseded", ids: replaced.map((r) => r.old) });
    }
    // The pending suggestions of what was scanned: the history's
    // repositories, and anything at or under a walked workspace root.
    const roots = new Set((history?.repos ?? []).map((r) => r.repoRoot).filter((r): r is string => r !== null));
    for (const f of workspace?.findings ?? []) roots.add(f.repoRoot ?? f.root);
    for (const f of labelFindings) roots.add(f.repoRoot);
    const walked = (workspace?.roots ?? []).filter((r) => r.reason === undefined).map((r) => r.root);
    const under = (p: string): boolean => walked.some((w) => p === w || p.startsWith(w === "/" ? "/" : `${w}/`));
    return {
      axis: true,
      running: false,
      suggestions: this.pending().filter((v) => roots.has(v.repoRoot) || under(v.repoRoot)),
      filed,
      covered: gen.covered,
      counts,
      scan: history ? { repos: history.repos, counts: history.counts, capped: history.capped, limits: history.limits, ms: history.ms } : null,
      workspaceScan: workspace ? workspaceSummary(workspace) : null,
    };
  }

  /**
   * Plan 14 §14.4: file the model's suggestions (policy-model.ts
   * `rulesToSuggestions` for the names-only tier, `contentsToSuggestions`
   * for the contents tier, each already through the tightening check or,
   * for a contents answer below no-model, `judgeHumanLabelLock`: filed
   * `humanOnly`, applied only by a person, §14.11). The
   * same rules as the scans': a pending or dismissed key, or every subject
   * already locked by a pending or dismissed suggestion of any source, is
   * not filed; the per-repository cap is shared, and the scans' suggestions
   * were filed first (the model runs after them, on a preview the person
   * consented to).
   */
  fileModelSuggestions(suggestions: readonly Suggestion[]): { filed: string[]; counts: Pick<SuggestPolicyCounts, "filed" | "alreadyPending" | "dismissed" | "overCap" | "superseded"> } {
    const counts = { filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, superseded: this.refresh().length };
    const law = this.law();
    const lawHash = hashOf(law.document ?? {});
    const locked = this.deps.proposals.suggestionSubjects();
    const filed: string[] = [];
    const replaced: Array<{ old: string; by: string }> = [];
    for (const s of suggestions) {
      const subjects = s.edits.map(suggestionSubject).filter((x): x is string => x !== null);
      // The same rule as the scans' (`admit`): a model's single-file lock
      // stricter than every pending one on that file replaces them (a
      // `no-model` answer over a label mapped to `any-model`, §14.12).
      const replaces = this.admit(s, subjects, locked, counts);
      if (replaces === null) continue;
      for (const x of subjects) locked.pending.add(x);
      const ev = evaluateEdits(law, s.edits, { now: this.now() });
      const { edits, findingKey, ...data } = s;
      const p = this.deps.proposals.fileSuggestion({
        edits: edits as unknown as PolicyEdit[],
        findingKey,
        suggestion: data,
        tightens: ev.ok ? ev.delta.tightenings : [],
        editsHash: hashOf(edits),
        lawHash,
      });
      filed.push(p.id);
      for (const old of replaces) {
        this.deps.proposals.resolveProposal(old.id, "superseded", SCAN_REQUESTER, { supersededBy: p.id });
        replaced.push({ old: old.id, by: p.id });
      }
    }
    counts.filed = filed.length;
    counts.superseded += replaced.length;
    if (filed.length > 0) {
      this.deps.docs.log(`policy suggestions filed from a model run: ${filed.join(", ")} (they wait for the person)`);
      this.emit({ action: "filed", ids: filed });
    }
    if (replaced.length > 0) {
      this.deps.docs.log(`policy suggestions ${replaced.map((r) => `${r.old} (by ${r.by})`).join(", ")}: replaced by a stricter suggestion for the same file (superseded)`);
      this.emit({ action: "superseded", ids: replaced.map((r) => r.old) });
    }
    return { filed, counts };
  }

  /**
   * Plan 14 §13.4, §14.1: may `s` be filed, and which pending suggestions
   * does it replace? Null (and the skip counted) when its finding key is
   * pending or dismissed, when every subject it locks is already locked by a
   * pending or dismissed suggestion, or when its repository is at the cap.
   * When a pending suggestion already locks the same one path at a LOWER
   * level (a label mapped to any-model, then a scan or a model finds the
   * file needs no-model; or the mapping was raised), the stricter one
   * replaces it: the caller closes the old one `superseded` by the new one.
   * A dismissed one still blocks ("Not a secret" is about the file).
   */
  private admit(
    s: Suggestion,
    subjects: readonly string[],
    locked: { pending: Set<string>; denied: Set<string> },
    counts: Pick<SuggestPolicyCounts, "alreadyPending" | "dismissed" | "overCap">,
  ): PolicyProposal[] | null {
    let replaces: PolicyProposal[] = [];
    const blocking = this.deps.proposals.blockingSuggestion(s.findingKey);
    const pendingOn = subjects.length > 0 && subjects.every((x) => locked.pending.has(x))
      ? this.deps.proposals.listProposals({ status: "pending", kind: "suggestion" })
        .filter((p) => p.edits.some((e) => { const x = suggestionSubject(e); return x !== null && subjects.includes(x); }))
      : [];
    if (blocking && blocking.status === "pending" && stricterThanAll(s.edits, [blocking, ...pendingOn])) {
      replaces = [...new Map([blocking, ...pendingOn].map((p) => [p.id, p])).values()];
    } else if (!blocking && pendingOn.length > 0 && stricterThanAll(s.edits, pendingOn)) {
      replaces = pendingOn;
    } else if (blocking) {
      if (blocking.status === "pending") counts.alreadyPending++;
      else counts.dismissed++;
      return null;
    } else if (subjects.length > 0 && subjects.every((x) => locked.pending.has(x) || locked.denied.has(x))) {
      if (subjects.every((x) => locked.pending.has(x))) counts.alreadyPending++;
      else counts.dismissed++;
      return null;
    }
    const freed = replaces.filter((p) => p.suggestion?.repoRoot === s.repoRoot).length;
    if (this.deps.proposals.pendingSuggestionCount(s.repoRoot) - freed >= SUGGESTION_CAP_PER_REPO) {
      counts.overCap++;
      return null;
    }
    return replaces;
  }

  /** After a folder rule of the model applied (plan 14 §14.4): the pending
   *  scan suggestions it grouped that the law now covers close `superseded`
   *  by it. */
  private supersedeCovered(p: PolicyProposal, by: string): void {
    const covers = p.suggestion?.model?.covers ?? [];
    if (covers.length === 0) return;
    const labels = this.labelled();
    const closed: string[] = [];
    for (const id of covers) {
      const c = this.deps.proposals.getProposal(id);
      if (!c || c.kind !== "suggestion" || c.status !== "pending" || !this.covered(c, labels)) continue;
      this.deps.proposals.resolveProposal(id, "superseded", by, { supersededBy: p.id });
      closed.push(id);
    }
    if (closed.length > 0) {
      this.deps.docs.log(`policy suggestions ${closed.join(", ")}: covered by ${p.id}, which was applied (superseded)`);
      this.emit({ action: "superseded", ids: closed });
    }
  }

  /** Every pending suggestion (the answer while a scan still runs). */
  pending(): SuggestionView[] {
    return this.deps.proposals.listProposals({ status: "pending", kind: "suggestion" }).map(suggestionView);
  }

  list(status?: ProposalStatus): PolicySuggestionsResult {
    this.refresh();
    return { suggestions: this.deps.proposals.listProposals({ kind: "suggestion", ...(status ? { status } : {}) }).map(suggestionView) };
  }

  private pendingSuggestion(id: string): PolicyProposal {
    const p = this.deps.proposals.getProposal(id);
    if (!p || p.kind !== "suggestion") throw new OpError(`unknown policy suggestion: ${id}`);
    if (p.status !== "pending") throw new OpError(`policy suggestion ${id} is already ${p.status}`);
    return p;
  }

  /**
   * Apply one pending suggestion, only as a pure tightening of the law in
   * force. `via` says who did it: "agent-tighten" (applySuggestion on the
   * DATA socket, the channel the agent's own programs reach, so nobody there
   * is attested a person), "tighten" (applySuggestion on the admin channel)
   * or "proposal" (a human's resolvePolicyProposal on the admin channel).
   * Only "proposal" may apply a `humanOnly` lock; every other apply is a
   * pure tightening or nothing.
   */
  apply(id: string, rec: { via: "agent-tighten" | "tighten" | "proposal"; by: string }): ApplySuggestionResult {
    const p = this.pendingSuggestion(id);
    const refuse = (refused: Extract<ApplySuggestionResult, { applied: false }>["refused"], problems: string[]): ApplySuggestionResult =>
      ({ applied: false, refused, problems, suggestion: suggestionView(this.deps.proposals.getProposal(id)!) });
    const closeCovered = (): ApplySuggestionResult => {
      this.deps.proposals.resolveProposal(id, "superseded", rec.by);
      this.emit({ action: "superseded", ids: [id] });
      return refuse("covered", ["the law already covers this; the suggestion is closed"]);
    };
    if (this.covered(p, this.labelled())) return closeCovered();
    if (!knownOps(p.edits)) {
      const ops = [...new Set(p.edits.map((e) => e.op).filter((op) => !(POLICY_EDIT_OPS as readonly string[]).includes(op)))];
      return refuse("unsupported", [`this Mandu cannot apply ${ops.join(", ")} yet; the suggestion stays pending`]);
    }
    const before = this.deps.docs.document;
    const ev = evaluateEdits({ specId: getCurrentPolicy().specId, document: before }, p.edits, { by: SCAN_REQUESTER, now: this.now() });
    if (!ev.ok) return refuse("invalid", ev.problems);
    // Plan 14 §14.1: a sensitivity-label lock below no-model. Only a person
    // on the admin channel applies it (`via: "proposal"`), only as the one
    // new label on its own file (`judgeHumanLabelLock`, again now), and
    // never over a file the catalog or a label protects now (it would
    // override that protection): that closes it as covered.
    const humanLock = p.suggestion?.humanOnly === true ? singleLock(p.edits) : null;
    if (humanLock !== null) {
      if (rec.via !== "proposal") {
        return refuse("relaxes", ["this rule lets an AI read the file (any level but No AI), which only you can approve: apply it in the dashboard (Rules › Keys Mandu found)"]);
      }
      const unescaped = humanLock.path.replace(/\\([*?[\]\\])/g, "$1");
      if (this.deps.protectedNow?.(unescaped) === true) return closeCovered();
      const j = judgeHumanLabelLock({ specId: getCurrentPolicy().specId, document: before }, p.edits[0] as LockPathEdit, this.now());
      if (j.verdict === "covered") return closeCovered();
      if (j.verdict !== "ok") return refuse(j.verdict === "invalid" ? "invalid" : "relaxes", j.problems);
    } else if (ev.delta.relaxations.length > 0) {
      return refuse("relaxes", [`the law changed since the scan, and this would now loosen: ${ev.delta.relaxations.map((r) => r.subject).join(", ")}`]);
    }
    if (humanLock === null && ev.delta.tightenings.length === 0) return closeCovered();
    // What the change is: the tightenings, or (a person approving a label
    // lock below no-model) the one new label the delta lists as a relaxation.
    const changes = humanLock === null ? ev.delta.tightenings : ev.delta.relaxations;
    let changeId: string;
    try {
      // While a relaxing hand edit waits in Approvals, the suggestion is made
      // to the law and to the held edit alike (first-session tour item 17):
      // `mandu policy suggest` and the dashboard's Lock it no longer wait on
      // it, and the held edit stays held, judged again against the new law.
      this.deps.docs.applyGuarded(ev.document, {
        via: rec.via, requestedBy: rec.by,
        summary: `${rec.by} applied ${id}, suggested by Mandu's scan: ${changes.map((t) => t.subject).join(", ")}`,
      }, (held) => layerEdits(held, p.edits as PolicyEdit[], SCAN_REQUESTER, this.now()));
      changeId = this.deps.proposals.recordChange({
        via: rec.via, requestedBy: rec.by, sessionKey: null, edits: p.edits,
        delta: changes, revert: diffItems(before, ev.document), proposalId: id,
      }).id;
    } catch (err) {
      if (err instanceof StalePolicyError) return refuse("stale", [err.message]);
      throw err;
    }
    const resolved = this.deps.proposals.resolveProposal(id, "approved", rec.by, { changeId })!;
    this.emit({ action: "applied", ids: [id] });
    this.supersedeCovered(resolved, rec.by);
    return { applied: true, changeId, delta: changes, suggestion: suggestionView(resolved) };
  }

  /** ADMIN: "Not a secret". */
  dismiss(id: string, by: string): DismissSuggestionResult {
    this.pendingSuggestion(id);
    const p = this.deps.proposals.resolveProposal(id, "denied", by)!;
    this.deps.docs.log(`policy suggestion ${id} dismissed by ${by}: its finding is not filed again`);
    this.emit({ action: "dismissed", ids: [id] });
    return { suggestion: suggestionView(p) };
  }

  /** ADMIN: `resolvePolicyProposal` on a suggestion. Approve = apply (via
   *  "proposal"); a refusal is an error and it stays pending, except that
   *  "the law already says this" closes it. Deny = dismiss. */
  resolve(id: string, verdict: "approved" | "denied", by: string): ResolvePolicyProposalResult {
    if (verdict === "denied") return { proposal: proposalWire(this.deps.proposals.getProposal(this.dismiss(id, by).suggestion.id)!) };
    const r = this.apply(id, { via: "proposal", by });
    if (r.applied) return { proposal: proposalWire(this.deps.proposals.getProposal(id)!), changeId: r.changeId };
    if (r.refused === "covered") return { proposal: proposalWire(this.deps.proposals.getProposal(id)!) };
    throw new OpError(`policy suggestion ${id} was not applied (${r.refused}): ${r.problems.join("; ")}`);
  }
}
