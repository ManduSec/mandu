/**
 * policy-proposals — the human-decision state of the policy agent surface
 * (docs/design/ui/policy-surface.md §8.4.2, §8.4.5). Mandu-new.
 *
 * Two tables in mandu.db, beside `egress_approvals`, with the same shape of
 * life (SQLite-backed so a restart keeps them; the arbiter is the single
 * writer; one long-lived WAL connection to the shared file):
 *
 *   policy_proposals — a change a client asked for that RELAXES the law (or
 *     exceeded the tightening cap). It waits for a human: `pending` →
 *     `approved` | `denied`, or `superseded` when approval found the law had
 *     moved and the delta grew (the re-filed proposal names it). Bound to the
 *     law it was computed against (`lawHash`).
 *
 *     A proposal with a `diskHash` is a HELD DISK CHANGE (§4.6): policy.yaml
 *     was changed on disk while the arbiter ran and the change relaxes the
 *     law, so it is kept out of force until a human approves it. It carries
 *     no edits: approving loads the file's bytes with that hash. It keeps
 *     those bytes (`diskText`): declining restores the file to the law in
 *     force (policy-restore.ts), and the row is where the hand edit can be
 *     recovered from.
 *
 *     A row of kind `suggestion` (confidentiality-plan-14 §5.1) is a change
 *     Mandu's own scans generated (the git history, and since §13 the files
 *     on disk): filed only by the arbiter, as
 *     `mandu:scan`, with a finding key (dedup) and the review's facts. It is
 *     kept apart from the proposals a client filed (their caps, dedup and
 *     list); policy-suggestion-ops.ts owns its life.
 *
 *   policy_enforced — the policy.yaml content in force, per file path, so a
 *     start can restore it over content a human declined (policy-restore.ts).
 *
 *   policy_changes — every change a client made to the law THROUGH this
 *     surface (an agent's tightening, an approved proposal, an undo), with the
 *     items it touched and their prior values (`revert`, policy-edit.ts
 *     `diffItems`) so a human can Undo it without restoring the old file.
 *
 * The `reason` a client gives is stored AS WRITTEN (symbols included, capped
 * at REASON_MAX by the server) and treated as UNTRUSTED text everywhere: the
 * agent may have been steered by a page it read (§3.6). Nothing here renders
 * or interprets it.
 */
import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import Database from "../db/sqlite.js";
import type { DeltaChange } from "./policy-delta.js";
import type { PolicyEdit, RevertItem } from "./policy-edit.js";
import type { Suggestion } from "./policy-suggestions.js";

export type ProposalStatus = "pending" | "approved" | "denied" | "superseded";

/** `proposal`: a change a client asked for (§4.5) or a held disk change
 *  (§4.6). `suggestion`: a change Mandu's own scan generated (plan 14 §5.1);
 *  only the arbiter files one, as `mandu:scan`. */
export type ProposalKind = "proposal" | "suggestion";

/** `requestedBy` of every suggestion: the arbiter ran the scan. No client
 *  can file a suggestion or name this principal. */
export const SCAN_REQUESTER = "mandu:scan";

/** What a suggestion row keeps besides its edits (plan 14 §5.1): the review's
 *  facts. No field carries a secret value (policy-suggestions.ts). */
export type SuggestionData = Omit<Suggestion, "edits" | "findingKey">;

export interface PolicyProposal {
  id: string;
  /** A suggestion's are `SuggestionEdit`s (policy-suggestions.ts):
   *  `lock-path` and `lock-blob` (plan 14 §8.2) at `no-model`. */
  edits: PolicyEdit[];
  /** The client's words: UNTRUSTED text (§3.6). */
  reason: string | null;
  /** `agent:<sessionKey>`, `assistant`, `human:<who>`. */
  requestedBy: string;
  sessionKey: string | null;
  /** What approving would give up (the delta at filing). */
  relaxes: DeltaChange[];
  tightens: DeltaChange[];
  /** canonical-JSON hash of `edits` — the dedupe key among pending proposals. */
  editsHash: string;
  /** canonical-JSON hash of the document the delta was computed against. */
  lawHash: string;
  status: ProposalStatus;
  createdAt: number;
  resolvedAt: number | null;
  resolvedBy: string | null;
  /** The change it became (approved), or the proposal that replaced it (superseded). */
  changeId: string | null;
  supersededBy: string | null;
  /** A held disk change (§4.6): sha256 of the policy.yaml bytes it would
   *  load (`absent` for a removed file); null for an edit proposal. */
  diskHash: string | null;
  /** A held disk change: the file's text as held (null for a removed file,
   *  and for an edit proposal). Admin-only on the wire: the data plane never
   *  reads a hand edit's text. */
  diskText?: string | null;
  kind: ProposalKind;
  /** A suggestion's dedup key (policy-suggestions.ts `findingKeyOf`): a
   *  pending or dismissed (denied) key is never filed again. */
  findingKey: string | null;
  /** A suggestion's review facts; null for a proposal. */
  suggestion: SuggestionData | null;
  /** The items the edits were built from (`policyPropose.basedOn`,
   *  policy-surface.md §8.4.6 "An item-level version"), each with the
   *  sha256 of its value as canonical JSON when filed (unkeyed, so it
   *  survives a restart; never on the wire): approving refuses once one
   *  is another. Absent or empty: none named. */
  basedOn?: ProposalItemBase[] | null;
}

/** One item a proposal was built from, as it was when filed. */
export interface ProposalItemBase {
  section: string;
  key: string;
  hash: string;
}

/** `requestedBy` of a held disk change: whoever wrote the file is unknown. */
export const DISK_REQUESTER = "file";

/** agent-tighten = a data-plane tightening (the agent's own `policyPropose`,
 *  or a scan suggestion applied with `applySuggestion` on the data socket);
 *  tighten = an admin-channel one.
 *  The rest are writes that do not pass through the policy surface, recorded
 *  so every rule has a known origin (dashboard.md §4.25j): `disk` = a hand
 *  edit picked up from the file (NOT undoable: Undo would rewrite the
 *  person's file and drop its comments), `apply` / `mint-rule` /
 *  `export-labels` = the developer view's writes, `pin-reader` = Mandu
 *  pinning a program the person allowed, `move-labels` = rules made on the
 *  dashboard before they lived in policy.yaml, moved there unchanged (NOT
 *  undoable: the rows it moved are gone from mandu.db, so Undo would drop
 *  them; dashboard.md §4.25m). */
export type ChangeVia =
  | "agent-tighten" | "tighten" | "proposal" | "undo"
  | "disk" | "apply" | "mint-rule" | "export-labels" | "pin-reader" | "move-labels";

/** The vias recorded from the document store's audit hook, not by the
 *  policy surface itself (which records its own changes). */
export const OUTSIDE_VIAS: ReadonlySet<ChangeVia> = new Set(["disk", "apply", "mint-rule", "export-labels", "pin-reader", "move-labels"]);

export interface PolicyChangeRecord {
  id: string;
  via: ChangeVia;
  requestedBy: string;
  sessionKey: string | null;
  edits: PolicyEdit[];
  /** The rows the change made (the delta), for History. */
  delta: DeltaChange[];
  revert: RevertItem[];
  proposalId: string | null;
  createdAt: number;
  undoneAt: number | null;
  /** The change that undid this one. */
  undoneBy: string | null;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS policy_proposals (
  id            TEXT PRIMARY KEY,
  edits         TEXT NOT NULL,
  reason        TEXT,
  requested_by  TEXT NOT NULL,
  session_key   TEXT,
  relaxes       TEXT NOT NULL,
  tightens      TEXT NOT NULL,
  edits_hash    TEXT NOT NULL,
  law_hash      TEXT NOT NULL,
  status        TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  resolved_at   INTEGER,
  resolved_by   TEXT,
  change_id     TEXT,
  superseded_by TEXT,
  disk_hash     TEXT,
  disk_text     TEXT,
  kind          TEXT,
  finding_key   TEXT,
  suggestion    TEXT,
  based_on      TEXT
);
CREATE TABLE IF NOT EXISTS policy_enforced (
  path          TEXT PRIMARY KEY,
  hash          TEXT NOT NULL,
  text          TEXT,
  at            INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_changes (
  id            TEXT PRIMARY KEY,
  via           TEXT NOT NULL,
  requested_by  TEXT NOT NULL,
  session_key   TEXT,
  edits         TEXT NOT NULL,
  delta         TEXT NOT NULL,
  revert        TEXT NOT NULL,
  proposal_id   TEXT,
  created_at    INTEGER NOT NULL,
  undone_at     INTEGER,
  undone_by     TEXT
);
CREATE TABLE IF NOT EXISTS suggest_scans (
  root          TEXT PRIMARY KEY,
  finished_at   INTEGER NOT NULL
);
`;

/** Plan 14 §5.5: the roots whose last finished scan is kept (the newest;
 *  one row per workspace a launch scanned). */
export const SUGGEST_SCANS_MAX = 256;

function parseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export interface PolicyProposalStoreOptions {
  /** mandu.db path; omitted = in-memory only (unit fixtures). */
  dbPath?: string;
  now?: () => number;
}

export class PolicyProposalStore {
  private readonly proposals = new Map<string, PolicyProposal>();
  private readonly changes = new Map<string, PolicyChangeRecord>();
  private readonly enforced = new Map<string, { hash: string; text: string | null }>();
  /** Plan 14 §5.5: when a `suggestPolicy` scan of every source last
   *  finished over each root (`suggest_scans`, so an arbiter restart keeps
   *  it). */
  private readonly suggestScans = new Map<string, number>();
  private propSeq = 0;
  private changeSeq = 0;
  private readonly now: () => number;
  private readonly db?: InstanceType<typeof Database>;

  constructor(opts: PolicyProposalStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    if (opts.dbPath !== undefined) {
      const dir = join(opts.dbPath, "..");
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      this.db = new Database(opts.dbPath);
      this.db.pragma("journal_mode = WAL");
      this.db.exec(SCHEMA_SQL);
      // A table created before held disk changes (§4.6) gains the column.
      const cols = this.db.prepare("PRAGMA table_info(policy_proposals)").all() as Array<{ name: string }>;
      if (!cols.some((c) => c.name === "disk_hash")) this.db.exec("ALTER TABLE policy_proposals ADD COLUMN disk_hash TEXT");
      if (!cols.some((c) => c.name === "disk_text")) this.db.exec("ALTER TABLE policy_proposals ADD COLUMN disk_text TEXT");
      // ... and before suggestions (plan 14 §5.1). NULL reads as the old
      // meaning: kind NULL = a proposal, no finding key, no review facts.
      // ... and before item-level versions (§8.4.6): NULL = none named.
      for (const col of ["kind", "finding_key", "suggestion", "based_on"]) {
        if (!cols.some((c) => c.name === col)) this.db.exec(`ALTER TABLE policy_proposals ADD COLUMN ${col} TEXT`);
      }
      try {
        this.hydrate();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[policy-proposals] hydrate failed, starting empty: ${(err as Error).message}`);
      }
    }
  }

  private hydrate(): void {
    if (!this.db) return;
    for (const r of this.db.prepare("SELECT * FROM policy_proposals").all() as Array<Record<string, unknown>>) {
      const p: PolicyProposal = {
        id: String(r.id),
        edits: parseJson(r.edits as string, []),
        reason: (r.reason as string | null) ?? null,
        requestedBy: String(r.requested_by),
        sessionKey: (r.session_key as string | null) ?? null,
        relaxes: parseJson(r.relaxes as string, []),
        tightens: parseJson(r.tightens as string, []),
        editsHash: String(r.edits_hash),
        lawHash: String(r.law_hash),
        status: r.status as ProposalStatus,
        createdAt: Number(r.created_at),
        resolvedAt: (r.resolved_at as number | null) ?? null,
        resolvedBy: (r.resolved_by as string | null) ?? null,
        changeId: (r.change_id as string | null) ?? null,
        supersededBy: (r.superseded_by as string | null) ?? null,
        diskHash: (r.disk_hash as string | null) ?? null,
        diskText: (r.disk_text as string | null) ?? null,
        kind: r.kind === "suggestion" ? "suggestion" : "proposal",
        findingKey: (r.finding_key as string | null) ?? null,
        suggestion: parseJson<SuggestionData | null>(r.suggestion as string | null, null),
        basedOn: parseJson<ProposalItemBase[] | null>(r.based_on as string | null, null),
      };
      this.proposals.set(p.id, p);
      this.propSeq = Math.max(this.propSeq, seqOf(p.id, "pp-"));
    }
    for (const r of this.db.prepare("SELECT * FROM policy_changes").all() as Array<Record<string, unknown>>) {
      const c: PolicyChangeRecord = {
        id: String(r.id),
        via: r.via as ChangeVia,
        requestedBy: String(r.requested_by),
        sessionKey: (r.session_key as string | null) ?? null,
        edits: parseJson(r.edits as string, []),
        delta: parseJson(r.delta as string, []),
        revert: parseJson(r.revert as string, []),
        proposalId: (r.proposal_id as string | null) ?? null,
        createdAt: Number(r.created_at),
        undoneAt: (r.undone_at as number | null) ?? null,
        undoneBy: (r.undone_by as string | null) ?? null,
      };
      this.changes.set(c.id, c);
      this.changeSeq = Math.max(this.changeSeq, seqOf(c.id, "pc-"));
    }
    for (const r of this.db.prepare("SELECT root, finished_at FROM suggest_scans").all() as Array<{ root: unknown; finished_at: unknown }>) {
      // Only what a scan could have written: an absolute root, a time.
      if (typeof r.root === "string" && r.root.startsWith("/") && typeof r.finished_at === "number" && Number.isFinite(r.finished_at)) {
        this.suggestScans.set(r.root, r.finished_at);
      }
    }
  }

  private persistProposal(p: PolicyProposal): void {
    if (!this.db) return;
    this.db.prepare(
      `INSERT INTO policy_proposals (id, edits, reason, requested_by, session_key, relaxes, tightens, edits_hash, law_hash, status, created_at, resolved_at, resolved_by, change_id, superseded_by, disk_hash, disk_text, kind, finding_key, suggestion, based_on)
       VALUES (@id, @edits, @reason, @requestedBy, @sessionKey, @relaxes, @tightens, @editsHash, @lawHash, @status, @createdAt, @resolvedAt, @resolvedBy, @changeId, @supersededBy, @diskHash, @diskText, @kind, @findingKey, @suggestion, @basedOn)
       ON CONFLICT(id) DO UPDATE SET status = excluded.status, resolved_at = excluded.resolved_at,
         resolved_by = excluded.resolved_by, change_id = excluded.change_id, superseded_by = excluded.superseded_by`,
    ).run({
      ...p, diskText: p.diskText ?? null, edits: JSON.stringify(p.edits), relaxes: JSON.stringify(p.relaxes), tightens: JSON.stringify(p.tightens),
      suggestion: p.suggestion ? JSON.stringify(p.suggestion) : null,
      basedOn: p.basedOn && p.basedOn.length > 0 ? JSON.stringify(p.basedOn) : null,
    });
  }

  private persistChange(c: PolicyChangeRecord): void {
    if (!this.db) return;
    this.db.prepare(
      `INSERT INTO policy_changes (id, via, requested_by, session_key, edits, delta, revert, proposal_id, created_at, undone_at, undone_by)
       VALUES (@id, @via, @requestedBy, @sessionKey, @edits, @delta, @revert, @proposalId, @createdAt, @undoneAt, @undoneBy)
       ON CONFLICT(id) DO UPDATE SET undone_at = excluded.undone_at, undone_by = excluded.undone_by`,
    ).run({ ...c, edits: JSON.stringify(c.edits), delta: JSON.stringify(c.delta), revert: JSON.stringify(c.revert) });
  }

  // ── proposals ──────────────────────────────────────────────────────────────

  file(
    p: Omit<PolicyProposal, "id" | "status" | "createdAt" | "resolvedAt" | "resolvedBy" | "changeId" | "supersededBy" | "diskHash" | "diskText" | "kind" | "findingKey" | "suggestion">
      & { diskHash?: string | null; diskText?: string | null },
  ): PolicyProposal {
    return this.insert({ ...p, kind: "proposal", findingKey: null, suggestion: null });
  }

  /** File a suggestion (plan 14 §5.1). The arbiter's scan is the only
   *  caller; the requester is always {@link SCAN_REQUESTER}. */
  fileSuggestion(p: { edits: PolicyEdit[]; findingKey: string; suggestion: SuggestionData; tightens: DeltaChange[]; editsHash: string; lawHash: string }): PolicyProposal {
    return this.insert({
      edits: p.edits, reason: null, requestedBy: SCAN_REQUESTER, sessionKey: null, relaxes: [], tightens: p.tightens,
      editsHash: p.editsHash, lawHash: p.lawHash, kind: "suggestion", findingKey: p.findingKey, suggestion: p.suggestion,
    });
  }

  private insert(
    p: Omit<PolicyProposal, "id" | "status" | "createdAt" | "resolvedAt" | "resolvedBy" | "changeId" | "supersededBy" | "diskHash" | "diskText">
      & { diskHash?: string | null; diskText?: string | null },
  ): PolicyProposal {
    const proposal: PolicyProposal = {
      ...p,
      diskHash: p.diskHash ?? null,
      ...(p.diskHash ? { diskText: p.diskText ?? null } : {}),
      id: `pp-${String(++this.propSeq).padStart(6, "0")}`,
      status: "pending",
      createdAt: this.now(),
      resolvedAt: null,
      resolvedBy: null,
      changeId: null,
      supersededBy: null,
    };
    this.proposals.set(proposal.id, proposal);
    this.persistProposal(proposal);
    return proposal;
  }

  getProposal(id: string): PolicyProposal | undefined {
    return this.proposals.get(id);
  }

  /** The PENDING held disk change for these bytes, if any (§4.6). */
  pendingDisk(diskHash: string): PolicyProposal | undefined {
    for (const p of this.proposals.values()) if (p.status === "pending" && p.diskHash === diskHash) return p;
    return undefined;
  }

  /** A PENDING proposal with the same edit list, if any (the dedupe of §4.5).
   *  Suggestions are not proposals a client filed: they never match. */
  pendingWithEdits(editsHash: string): PolicyProposal | undefined {
    for (const p of this.proposals.values()) if (p.status === "pending" && p.kind === "proposal" && p.editsHash === editsHash) return p;
    return undefined;
  }

  /** Pending PROPOSALS (the §4.5 flood caps); suggestions have their own cap. */
  pendingCount(sessionKey?: string | null): number {
    let n = 0;
    for (const p of this.proposals.values()) {
      if (p.status !== "pending" || p.kind !== "proposal") continue;
      if (sessionKey !== undefined && p.sessionKey !== sessionKey) continue;
      n++;
    }
    return n;
  }

  /** `kind` omitted: both kinds. */
  listProposals(filter?: { status?: ProposalStatus; kind?: ProposalKind }): PolicyProposal[] {
    const all = [...this.proposals.values()].filter((p) => (!filter?.status || p.status === filter.status) && (!filter?.kind || p.kind === filter.kind));
    return all.sort((a, b) => b.createdAt - a.createdAt || b.id.localeCompare(a.id));
  }

  /** The suggestion filed for `findingKey` that still blocks a refiling: a
   *  PENDING one, or a DISMISSED (denied) one (plan 14 §5.1). */
  blockingSuggestion(findingKey: string): PolicyProposal | undefined {
    for (const p of this.proposals.values()) {
      if (p.kind === "suggestion" && p.findingKey === findingKey && (p.status === "pending" || p.status === "denied")) return p;
    }
    return undefined;
  }

  /** What the PENDING and the DISMISSED (denied) suggestions lock, of any
   *  source (plan 14 §13.4: one suggestion per file across the history and
   *  the workspace scans, and "Not a secret" is about the file, whichever
   *  scan found it). Each edit's subject: `path:<lock path>` or
   *  `blob:<id>` (`suggestionSubject`). */
  suggestionSubjects(): { pending: Set<string>; denied: Set<string> } {
    const pending = new Set<string>();
    const denied = new Set<string>();
    for (const p of this.proposals.values()) {
      if (p.kind !== "suggestion" || (p.status !== "pending" && p.status !== "denied")) continue;
      const into = p.status === "pending" ? pending : denied;
      for (const e of p.edits) {
        const s = suggestionSubject(e);
        if (s !== null) into.add(s);
      }
    }
    return { pending, denied };
  }

  /** Pending suggestions for one repository (the per-repository cap). */
  pendingSuggestionCount(repoRoot: string): number {
    let n = 0;
    for (const p of this.proposals.values()) if (p.kind === "suggestion" && p.status === "pending" && p.suggestion?.repoRoot === repoRoot) n++;
    return n;
  }

  resolveProposal(id: string, status: "approved" | "denied" | "superseded", by: string, link?: { changeId?: string; supersededBy?: string }): PolicyProposal | undefined {
    const p = this.proposals.get(id);
    if (!p || p.status !== "pending") return undefined;
    p.status = status;
    p.resolvedAt = this.now();
    p.resolvedBy = by;
    if (link?.changeId) p.changeId = link.changeId;
    if (link?.supersededBy) p.supersededBy = link.supersededBy;
    this.persistProposal(p);
    return p;
  }

  // ── the content in force (policy-restore.ts) ──────────────────────────────

  /** The policy.yaml content in force for `path` as last recorded, or null. */
  enforcedPolicy(path: string): { hash: string; text: string | null } | null {
    const mem = this.enforced.get(path);
    if (mem) return { ...mem };
    if (!this.db) return null;
    const r = this.db.prepare("SELECT hash, text FROM policy_enforced WHERE path = ?").get(path) as { hash: string; text: string | null } | undefined;
    return r ? { hash: String(r.hash), text: r.text ?? null } : null;
  }

  /** Record the content in force for `path` (the arbiter calls this on every
   *  change of the law it read from, or wrote to, that file). */
  recordEnforced(path: string, e: { hash: string; text: string | null }): void {
    const prev = this.enforced.get(path);
    if (prev && prev.hash === e.hash) return;
    this.enforced.set(path, { hash: e.hash, text: e.text });
    if (!this.db) return;
    this.db.prepare(
      `INSERT INTO policy_enforced (path, hash, text, at) VALUES (@path, @hash, @text, @at)
       ON CONFLICT(path) DO UPDATE SET hash = excluded.hash, text = excluded.text, at = excluded.at`,
    ).run({ path, hash: e.hash, text: e.text, at: this.now() });
  }

  // ── the last finished scan (plan 14 §5.5) ─────────────────────────────────

  /** Each root a `suggestPolicy` scan of every source finished over, with
   *  when (the server's `earlierScanAt` reads it). */
  suggestScansFinished(): ReadonlyMap<string, number> {
    return this.suggestScans;
  }

  /** Record that a scan of every source finished over `roots` at `at`. At
   *  most SUGGEST_SCANS_MAX roots are kept, the newest. */
  recordSuggestScan(roots: readonly string[], at: number): void {
    for (const root of roots) this.suggestScans.set(root, at);
    const drop: string[] = [];
    if (this.suggestScans.size > SUGGEST_SCANS_MAX) {
      const oldest = [...this.suggestScans].sort((a, b) => a[1] - b[1]).slice(0, this.suggestScans.size - SUGGEST_SCANS_MAX);
      for (const [root] of oldest) {
        this.suggestScans.delete(root);
        drop.push(root);
      }
    }
    if (!this.db) return;
    try {
      const put = this.db.prepare(
        `INSERT INTO suggest_scans (root, finished_at) VALUES (?, ?)
         ON CONFLICT(root) DO UPDATE SET finished_at = excluded.finished_at`,
      );
      const del = this.db.prepare("DELETE FROM suggest_scans WHERE root = ?");
      this.db.transaction(() => {
        for (const root of roots) put.run(root, at);
        for (const root of drop) del.run(root);
      })();
    } catch (err) {
      // A speed hint only: the next arbiter waits for its first scan again.
      // eslint-disable-next-line no-console
      console.error(`[policy-proposals] suggest_scans write failed: ${(err as Error).message}`);
    }
  }

  // ── changes ────────────────────────────────────────────────────────────────

  recordChange(c: Omit<PolicyChangeRecord, "id" | "createdAt" | "undoneAt" | "undoneBy">): PolicyChangeRecord {
    const change: PolicyChangeRecord = { ...c, id: `pc-${String(++this.changeSeq).padStart(6, "0")}`, createdAt: this.now(), undoneAt: null, undoneBy: null };
    this.changes.set(change.id, change);
    this.persistChange(change);
    return change;
  }

  getChange(id: string): PolicyChangeRecord | undefined {
    return this.changes.get(id);
  }

  markUndone(id: string, undoneBy: string): void {
    const c = this.changes.get(id);
    if (!c) return;
    c.undoneAt = this.now();
    c.undoneBy = undoneBy;
    this.persistChange(c);
  }

  /** Agent tightenings a session has applied (the per-session cap, §3.5):
   *  the agent's OWN edits. A suggestion of Mandu's scan applied on the data
   *  plane (also `agent-tighten`, carrying its `proposalId`) is bounded by
   *  the scan's filing cap instead, and does not spend a session's budget. */
  tighteningsBy(sessionKey: string | null): number {
    let n = 0;
    for (const c of this.changes.values()) if (c.via === "agent-tighten" && c.proposalId === null && c.sessionKey === sessionKey) n++;
    return n;
  }

  listChanges(limit = 100): PolicyChangeRecord[] {
    return [...this.changes.values()].sort((a, b) => b.createdAt - a.createdAt || b.id.localeCompare(a.id)).slice(0, limit);
  }

  close(): void {
    this.db?.close();
  }
}

/** What a suggestion's edit locks: `path:<lock path>` for a `lock-path`,
 *  `blob:<id>` for a `lock-blob`, null for anything else. Both scans write
 *  a lock path as the literal label path (policy-suggestions.ts
 *  `literalLabelPath`), so a path is spelled the same by either. */
export function suggestionSubject(e: { op: string }): string | null {
  const x = e as { op: string; path?: unknown; blob?: unknown };
  if (x.op === "lock-path" && typeof x.path === "string") return `path:${x.path}`;
  if (x.op === "lock-blob" && typeof x.blob === "string") return `blob:${x.blob}`;
  return null;
}

function seqOf(id: string, prefix: string): number {
  const n = parseInt(id.replace(prefix, ""), 10);
  return Number.isFinite(n) ? n : 0;
}
