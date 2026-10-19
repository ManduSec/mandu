/**
 * policy-agent-ops — the arbiter side of the policy agent surface
 * (docs/design/ui/policy-surface.md §8.4.2). Mandu-new.
 *
 * The server's dispatch delegates here for `policyPropose`, `policyProposals`,
 * `policyChanges`, `resolvePolicyProposal`, `undoPolicyChange` and
 * `policyExplain`. The CHANNEL rule is the server's (`ADMIN_ONLY_OPS`: the
 * resolve and undo ops never reach this class from the data socket); the
 * MONOTONIC rule is here: a change is applied from the data plane only when
 * `policyDelta` proves it tightens (policy-delta.ts), and everything else is a
 * proposal a human decides.
 *
 * Every write goes through `PolicyDocumentStore.applyGuarded`, so a hand edit
 * made inside the poll window is loaded instead of overwritten, and a change
 * made while a relaxing hand edit is held is made to the law and to the held
 * edit alike (tour item 17): it neither waits on the hold nor releases it.
 *
 * A policy.yaml change seen on DISK that relaxes the law is held by the store
 * (§4.6); this class files it as a proposal with a `diskHash` (listener set
 * in the constructor), and `resolve` approves it by loading exactly the held
 * bytes, or declines it, which restores the file to the law in force
 * (policy-restore.ts); the row keeps the declined text.
 */
import { compilePolicy, connectAllowSpecs, expandListsInDocument, getCurrentPolicy, panelRowIds, relaxationsOf, type ModelEndpoint } from "../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../policy/load-policy.js";
import { policyDelta, type DeltaChange } from "../policy/policy-delta.js";
import { StalePolicyError, type DiskHold, type PolicyDocumentStore } from "../policy/policy-document-store.js";
import { applyEdits, canonicalJson, diffItems, evaluateEdits, itemStates, itemValue, modelEditProblems, revertConflicts, revertItems, type PolicyEdit } from "../policy/policy-edit.js";
import { DISK_REQUESTER, type ChangeVia, type PolicyChangeRecord, type PolicyProposal, type PolicyProposalStore, type ProposalItemBase } from "../policy/policy-proposals.js";
import type { PathLabel } from "../policy/path-labels.js";
import type {
  ModelEndpointWire,
  PolicyChangeWire,
  PolicyChangesResult,
  PolicyExplainResult,
  PolicyProposalWire,
  PolicyProposeOpRequest,
  PolicyProposeResult,
  PolicyPreviewResult,
  ResolvePolicyProposalResult,
  UndoPolicyChangeResult,
} from "./protocol.js";
import { createHash } from "node:crypto";

/** §3.5: the 21st tightening from one session becomes a proposal. */
export const TIGHTEN_CAP_PER_SESSION = 20;
/** §4.3a: admin-channel requesters that relay a MODEL's edits (the
 *  dashboard's Describe box) and so are refused model-endpoint ops, as the
 *  data plane is. */
export const MODEL_EDIT_BARRED_REQUESTERS: ReadonlySet<string> = new Set(["assistant"]);
/** §4.5 flood limits. */
export const PENDING_CAP_PER_SESSION = 10;
export const PENDING_CAP_TOTAL = 50;
export const REASON_MAX = 280;

/** A session key as attribution: bounded, or `unknown`. Self-asserted by the
 *  caller, so it is an identity for caps and display, never for authority. */
const SESSION_KEY = /^[A-Za-z0-9_.:@-]{1,128}$/;

/** §4.4: every string policyExplain carries is a bounded token. */
const TOKEN = /^[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{1,200}$/;
export const WITHHELD = "(withheld)";
export function token(v: string): string {
  return TOKEN.test(v) ? v : WITHHELD;
}

/**
 * The fields of a declared model (plan 11 D2) the projection carries, in
 * order. The list is an allow-list: a field added to `ModelEndpoint` is not
 * shown until it is named here. A string field becomes a token (or
 * WITHHELD); a boolean is kept only when true (the compiled list writes an
 * optional flag such as `helper` only when true, and `local` is always
 * present). Nothing here is a secret: `tokenEnv` is the NAME of the variable
 * that holds the key, and the value is never read by this code.
 */
export const EXPLAIN_MODEL_FIELDS = ["name", "url", "wire", "model", "local", "tokenEnv", "helper", "allowPlainHttp"] as const;

/** A model's address for a configuring model: the URL without its query or
 *  fragment (either could carry a key), and never one with credentials (the
 *  file validator refuses those; this is the second line). */
export function explainModelUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return WITHHELD;
  }
  if (u.username !== "" || u.password !== "") return WITHHELD;
  if (u.search === "" && u.hash === "") return token(url);
  u.search = "";
  u.hash = "";
  return token(u.toString());
}

/** One declared model as the read view lists it (§4.4): read-only data. */
export function explainModel(m: ModelEndpoint): ModelEndpointWire {
  const src = m as unknown as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of EXPLAIN_MODEL_FIELDS) {
    const v = src[k];
    if (k === "local") out[k] = v === true;
    else if (k === "url") out[k] = typeof v === "string" ? explainModelUrl(v) : WITHHELD;
    else if (typeof v === "string") out[k] = token(v);
    else if (v === true) out[k] = true;
  }
  return out as unknown as ModelEndpointWire;
}

export interface PolicyAgentOpsDeps {
  docs: PolicyDocumentStore;
  proposals: PolicyProposalStore;
  /** Pending egress asks: destination + count (the gate's queue). */
  pendingAsks: () => Array<{ destination: string; count: number }>;
  /** Locked-file labels that live in mandu.db (the dashboard's "Lock it"). */
  dbLabels: () => PathLabel[];
  ruleHits: () => Record<string, { hits: number }>;
  hostOf: (destination: string) => string;
  /** Plan 14 §5.2: `resolvePolicyProposal` on a SUGGESTION (the scan's
   *  kind) is answered by the suggestion ops (policy-suggestion-ops.ts). */
  resolveSuggestion?: (id: string, verdict: "approved" | "denied", by: string) => ResolvePolicyProposalResult;
  now?: () => number;
}

export class OpError extends Error {}

/** `resolvedBy` of a proposal closed because the law in force already says
 *  what it asked for (tour item 17; `retireSatisfied`). The `mandu:` prefix
 *  is the arbiter's own: no client may claim it. */
export const IN_FORCE_RESOLVER = "mandu:in-force";

function hashOf(v: unknown): string {
  return createHash("sha256").update(canonicalJson(v)).digest("hex").slice(0, 32);
}

/** `resolvedBy` of a proposal closed because an item it was built from
 *  changed before it was approved (policy-surface.md §8.4.6 "An item-level
 *  version"). */
export const STALE_RESOLVER = "mandu:stale";
/** At most this many items in one `basedOn`. */
export const BASED_ON_MAX = 64;

/** `policyPropose.basedOn` read: each `{ section, key, version }`, or the
 *  problem. Absent = none named. */
export function parseBasedOn(v: unknown): { ok: true; items: Array<{ section: string; key: string; version: string }> } | { ok: false; problem: string } {
  if (v === undefined || v === null) return { ok: true, items: [] };
  if (!Array.isArray(v) || v.length > BASED_ON_MAX) return { ok: false, problem: `basedOn: must be a list of at most ${BASED_ON_MAX} { section, key, version }` };
  const items: Array<{ section: string; key: string; version: string }> = [];
  for (const [i, b] of v.entries()) {
    const o = b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
    if (!o || typeof o.section !== "string" || !/^[a-z_-]{1,32}$/.test(o.section) || typeof o.key !== "string" || o.key === "" || o.key.length > 1024
      || typeof o.version !== "string" || !/^[0-9a-f]{32}$/.test(o.version)) {
      return { ok: false, problem: `basedOn[${i}]: must be { section, key, version } as policyDocument's itemVersions gives them` };
    }
    items.push({ section: o.section, key: o.key, version: o.version });
  }
  return { ok: true, items };
}

/** An item as `section key`, the way a stale refusal names it. */
function itemName(b: { section: string; key: string }): string {
  return `${b.section} ${b.key.replace("\0", " ")}`;
}

/** The items of `based` whose value in `doc` is not what it was when the
 *  proposal was filed. */
function movedSince(doc: PolicyFileConfig | null, based: readonly ProposalItemBase[] | null | undefined): string[] {
  return (based ?? []).filter((b) => hashOf(itemValue(doc, b.section, b.key) ?? null) !== b.hash).map(itemName);
}

/** The same edits made to a held disk change's document (§4.6), or null
 *  when they do not apply to it (they name something it removed). The
 *  suggestion ops layer an applied suggestion the same way. */
export function layerEdits(held: PolicyFileConfig | null, edits: readonly PolicyEdit[], by: string, now: number): PolicyFileConfig | null {
  if (edits.length === 0) return null;
  const r = applyEdits(held, edits, { by, now });
  return r.ok ? r.document : null;
}

function deltaKeys(d: readonly DeltaChange[]): Set<string> {
  return new Set(d.map((c) => `${c.facet}\0${c.subject}`));
}

/** A proposal on the wire. A held disk change's text (`diskText`, the
 *  person's hand edit) goes only to the admin channel: the data plane (the
 *  policy agent) reads the law through policyExplain's bounded tokens. */
export function proposalWire(p: PolicyProposal, channel: "admin" | "data" = "admin"): PolicyProposalWire {
  // `basedOn` (unkeyed hashes of the items it was built from) stays in the
  // arbiter: an unkeyed hash of one entry could test a guess of its value.
  const { diskText, basedOn: _basedOn, ...rest } = p;
  return { ...rest, edits: [...p.edits], ...(channel === "admin" && p.diskHash !== null ? { diskText: diskText ?? null } : {}) };
}

export function changeWire(c: PolicyChangeRecord): PolicyChangeWire {
  const { revert: _revert, ...rest } = c;
  // A hand edit is not undone from here: that would rewrite the person's file.
  return { ...rest, edits: [...c.edits], undoable: c.undoneAt === null && c.via !== "undo" && c.via !== "disk" && c.via !== "move-labels" };
}

export class PolicyAgentOps {
  private readonly now: () => number;

  constructor(private readonly deps: PolicyAgentOpsDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.reconcileDiskHoldsAtStart();
    deps.docs.setDiskHoldListener((next, previous) => this.onDiskHold(next, previous));
    // A change made by hand and loaded at this start (an edit made while
    // Mandu was not running) can be what a pending proposal asked for.
    this.retireSatisfied();
  }

  /**
   * §4.6 at a restart (policy-restore.ts): the start (the server's
   * `reconcilePolicyFileAtStart`) already restored declined content and kept
   * a still-waiting change out of force, so the store holds it again. A
   * proposal still pending for exactly the held bytes stays pending (the
   * same card); any other pending one is closed as superseded (the file
   * moved on while the arbiter was down, or the change no longer relaxes
   * and was loaded).
   */
  private reconcileDiskHoldsAtStart(): void {
    const onDisk = this.deps.docs.diskHash;
    const held = this.deps.docs.heldChange;
    for (const p of this.deps.proposals.listProposals()) {
      if (p.diskHash === null) continue;
      if (p.status === "pending") {
        if (held && p.diskHash === held.hash) {
          this.deps.docs.log(`policy.yaml change ${p.id} still waits for a human; the content approved before it stays the law`);
          continue;
        }
        this.deps.proposals.resolveProposal(p.id, "superseded", "arbiter-start");
        if (p.diskHash === onDisk) {
          this.deps.docs.log(`policy.yaml change ${p.id} was still waiting for approval when the arbiter stopped; it no longer relaxes the law in force, so it was loaded`);
        }
      } else if (p.status === "denied" && p.diskHash === onDisk) {
        this.deps.docs.log(`WARNING: policy.yaml still holds the change ${p.id} that was declined (restoring the file failed); the declined change is NOT the law, and the arbiter keeps trying to restore the file`);
      }
    }
  }

  /** The store held a relaxing disk change (`next`) and/or ended one
   *  (`previous`: the file moved on or was written over). */
  private onDiskHold(next: DiskHold | null, previous: DiskHold | null): void {
    const old = previous ? this.deps.proposals.pendingDisk(previous.hash) : undefined;
    let filed: PolicyProposal | undefined;
    if (next) {
      const same = this.deps.proposals.pendingDisk(next.hash);
      filed = same && same !== old
        ? same
        : this.deps.proposals.file({
          edits: [], reason: null, requestedBy: DISK_REQUESTER, sessionKey: null,
          relaxes: next.delta.relaxations, tightens: next.delta.tightenings,
          editsHash: `disk:${next.hash}`, lawHash: hashOf(this.deps.docs.document ?? {}),
          diskHash: next.hash, diskText: next.text,
        });
      this.deps.docs.log(`policy.yaml change on disk held as ${filed.id}: it would relax ${next.delta.relaxations.length} rule(s); nothing changes until a human approves it`);
    }
    if (old && old !== filed) {
      this.deps.proposals.resolveProposal(old.id, "superseded", DISK_REQUESTER, filed ? { supersededBy: filed.id } : undefined);
    }
  }

  /** ADMIN: a human's verdict on a held disk change (§4.6). */
  private resolveDisk(p: PolicyProposal & { diskHash: string }, verdict: "approved" | "denied", by: string): ResolvePolicyProposalResult {
    if (verdict === "denied") {
      const r = this.deps.docs.declineDiskHold(p.diskHash);
      return { proposal: proposalWire(this.deps.proposals.resolveProposal(p.id, "denied", by)!), restored: r.restored };
    }
    const r = this.deps.docs.approveDiskHold(p.diskHash, {
      via: "proposal", requestedBy: by, summary: `${by} approved ${p.id}: the change made to policy.yaml on disk`,
    });
    if (r.applied) {
      const specId = this.specId();
      const d = policyDelta(compilePolicy({ specId, document: r.before }), compilePolicy({ specId, document: r.after }), { now: this.now() });
      const change = this.deps.proposals.recordChange({
        via: "proposal", requestedBy: by, sessionKey: null, edits: [],
        delta: [...d.relaxations, ...d.tightenings], revert: diffItems(r.before, r.after), proposalId: p.id,
      });
      const resolved = this.deps.proposals.resolveProposal(p.id, "approved", by, { changeId: change.id })!;
      return { proposal: proposalWire(resolved), changeId: change.id };
    }
    // The file moved on since it was held: what is on disk now was judged
    // afresh (applied, held anew, or refused as invalid). The approval never
    // covers bytes the human was not shown.
    const after = this.deps.proposals.getProposal(p.id)!;
    const closed = after.status === "pending" ? this.deps.proposals.resolveProposal(p.id, "superseded", by)! : after;
    const next = closed.supersededBy ? this.deps.proposals.getProposal(closed.supersededBy) : undefined;
    return { proposal: proposalWire(closed), ...(next && next.status === "pending" ? { refiled: proposalWire(next) } : {}) };
  }

  private specId() {
    return getCurrentPolicy().specId;
  }

  /** Write a document through the store and record the change.
   *
   * A relaxing hand edit waits in Approvals (§4.6). A change made through
   * the surface (an agent's tightening, a proposal a human approved, an
   * Undo) does not wait on it (first-session tour item 17): the law gets the
   * change, and `layer` makes the same change to the held document, which
   * the file keeps and the store judges again against the new law. Nothing
   * the held edit relaxes takes effect. By default the layer applies
   * `rec.edits`; an Undo passes its own (the same item-level revert). */
  private enact(
    before: PolicyFileConfig | null,
    after: PolicyFileConfig,
    rec: { via: ChangeVia; requestedBy: string; sessionKey: string | null; edits: PolicyEdit[]; delta: DeltaChange[]; proposalId: string | null },
    summary: string,
    layer: (held: PolicyFileConfig | null) => PolicyFileConfig | null = (held) => layerEdits(held, rec.edits, rec.requestedBy, this.now()),
  ): PolicyChangeRecord {
    this.deps.docs.applyGuarded(after, { via: rec.via, requestedBy: rec.requestedBy, summary }, layer);
    return this.deps.proposals.recordChange({ ...rec, revert: diffItems(before, after) });
  }

  /**
   * Close what the law in force already says (first-session tour item 17).
   * A pending proposal whose edits would change nothing the law means (the
   * human made the same change by hand, and a reload or a restart loaded it)
   * is closed `superseded` by {@link IN_FORCE_RESOLVER}; a held disk change is
   * judged again (`rejudgeHold`), so one the law has come to say is loaded
   * and its card closed. Never applies a relaxation: a proposal is closed
   * only when applying it would change nothing, and a held change is loaded
   * only when it relaxes nothing. Runs at start, before a proposal is filed
   * or decided, and on every read of the pending list.
   */
  retireSatisfied(): string[] {
    const closed: string[] = [];
    try {
      const held = this.deps.docs.heldChange;
      const card = held ? this.deps.proposals.pendingDisk(held.hash) : undefined;
      if (this.deps.docs.rejudgeHold() && card && this.deps.proposals.getProposal(card.id)?.status !== "pending") closed.push(card.id);
    } catch (err) {
      this.deps.docs.log(`judging the held policy.yaml change again failed (ignored; it stays held): ${(err as Error).message}`);
    }
    const doc = this.deps.docs.document;
    for (const p of this.deps.proposals.listProposals({ status: "pending", kind: "proposal" })) {
      if (p.diskHash !== null) continue;
      let ev: ReturnType<typeof evaluateEdits>;
      try {
        ev = evaluateEdits({ specId: this.specId(), document: doc }, p.edits, { by: p.requestedBy, now: this.now() });
      } catch {
        continue;
      }
      if (!ev.ok) continue;
      const same = canonicalJson(ev.document) === canonicalJson(doc ?? {})
        || (ev.delta.relaxations.length === 0 && ev.delta.tightenings.length === 0);
      if (!same) continue;
      if (this.deps.proposals.resolveProposal(p.id, "superseded", IN_FORCE_RESOLVER)) {
        closed.push(p.id);
        this.deps.docs.log(`policy change ${p.id} was waiting for approval, but the law in force already says it (a change made by hand and loaded); closed`);
      }
    }
    return closed;
  }

  /**
   * The law each pending change would make, for `mandu why` (tour item 17:
   * it never said a change was pending): a proposal's edits applied to the
   * law in force, a held disk change's document, a suggestion's edits.
   * Changes that no longer apply are left out.
   */
  pendingLaws(): Array<{ id: string; from: "file" | "agent" | "scan" | "other"; document: PolicyFileConfig | null }> {
    this.retireSatisfied();
    const doc = this.deps.docs.document;
    const held = this.deps.docs.heldChange;
    const out: Array<{ id: string; from: "file" | "agent" | "scan" | "other"; document: PolicyFileConfig | null }> = [];
    for (const p of this.deps.proposals.listProposals({ status: "pending" })) {
      if (p.diskHash !== null) {
        if (held && held.hash === p.diskHash) out.push({ id: p.id, from: "file", document: held.document });
        continue;
      }
      let ev: ReturnType<typeof evaluateEdits>;
      try {
        ev = evaluateEdits({ specId: this.specId(), document: doc }, p.edits, { by: p.requestedBy, now: this.now() });
      } catch {
        continue;
      }
      if (!ev.ok) continue;
      const from = p.kind === "suggestion" ? "scan" : p.requestedBy.startsWith("agent:") ? "agent" : "other";
      out.push({ id: p.id, from, document: ev.document });
    }
    return out;
  }

  propose(req: PolicyProposeOpRequest, channel: "admin" | "data"): PolicyProposeResult {
    // A pending proposal the law already says is not a duplicate to wait on.
    this.retireSatisfied();
    try {
      return this.proposeOne(req, channel);
    } finally {
      this.retireSatisfied();
    }
  }

  private proposeOne(req: PolicyProposeOpRequest, channel: "admin" | "data"): PolicyProposeResult {
    const sessionKey = typeof req.sessionKey === "string" && SESSION_KEY.test(req.sessionKey) ? req.sessionKey : null;
    // `mandu:*` names the arbiter itself (plan 14 §5.1: only its scan files,
    // as `mandu:scan`): no client, not even the admin channel, may claim it.
    const named = typeof req.requestedBy === "string" && req.requestedBy && !req.requestedBy.startsWith("mandu:") ? req.requestedBy.slice(0, 128) : "human";
    const requestedBy = channel === "admin" ? named : `agent:${sessionKey ?? "unknown"}`;
    if (req.reason !== undefined && typeof req.reason !== "string") {
      return { applied: false, refused: "invalid", problems: ["reason: must be a string"] };
    }
    const reason = typeof req.reason === "string" && req.reason !== "" ? req.reason.slice(0, REASON_MAX) : null;
    // §4.3a: a model never changes model endpoints. The data plane (the
    // policy agent) and the Describe box (admin, requestedBy "assistant")
    // are refused a model-endpoint op before anything is evaluated, filed
    // or written; Settings › Models and hand edits are the only ways.
    const barred = modelEditProblems(req.edits, channel === "data" ? "the policy agent" : "the Describe box");
    if (barred.length > 0 && (channel === "data" || MODEL_EDIT_BARRED_REQUESTERS.has(requestedBy))) {
      return { applied: false, refused: "invalid", problems: barred };
    }
    // §8.4.6 "An item-level version": the edits name the items they were
    // built from; one that changed since refuses the list, nothing written
    // or filed. Checked in this synchronous call, so nothing lands between
    // the check and the write.
    const based = parseBasedOn(req.basedOn);
    if (!based.ok) return { applied: false, refused: "invalid", problems: [based.problem] };
    const changed = based.items.filter((b) => this.deps.docs.itemVersion(b.section, b.key) !== b.version).map(itemName);
    if (changed.length > 0) {
      return { applied: false, refused: "stale", changed, problems: [`changed since it was read: ${changed.join(", ")}; nothing was changed`] };
    }
    const before = this.deps.docs.document;
    const ev = evaluateEdits({ specId: this.specId(), document: before }, req.edits, { by: requestedBy, now: this.now() });
    if (!ev.ok) return { applied: false, refused: "invalid", problems: ev.problems };
    const edits = req.edits as PolicyEdit[];
    // Kept on a filed proposal, so approving it later refuses the same way.
    const basedOn: ProposalItemBase[] = based.items.map((b) => ({ section: b.section, key: b.key, hash: hashOf(itemValue(before, b.section, b.key) ?? null) }));

    const capped = channel === "data" && this.deps.proposals.tighteningsBy(sessionKey) >= TIGHTEN_CAP_PER_SESSION;
    if (ev.tightening && !capped) {
      if (ev.delta.tightenings.length === 0 && canonicalJson(ev.document) === canonicalJson(before ?? {})) {
        return { applied: true, changeId: null, delta: [], note: "nothing to change: the law already says this" };
      }
      try {
        const change = this.enact(before, ev.document, {
          via: channel === "data" ? "agent-tighten" : "tighten",
          requestedBy, sessionKey, edits, delta: ev.delta.tightenings, proposalId: null,
        }, `${requestedBy} tightened the law: ${ev.delta.tightenings.map((t) => t.subject).join(", ") || "no effective change"}`);
        return { applied: true, changeId: change.id, delta: ev.delta.tightenings };
      } catch (err) {
        if (err instanceof StalePolicyError) return { applied: false, refused: "stale", problems: [err.message] };
        throw err;
      }
    }

    // The precondition is part of the identity: a pending proposal of the
    // same edits that names no item (or other versions) is not this one.
    const editsHash = basedOn.length > 0 ? hashOf({ edits, basedOn }) : hashOf(edits);
    const dup = this.deps.proposals.pendingWithEdits(editsHash);
    if (dup) return { applied: false, proposalId: dup.id, relaxes: dup.relaxes, why: dup.relaxes.length ? "relaxes" : "tightening-cap", duplicate: true };
    if (this.deps.proposals.pendingCount(sessionKey) >= PENDING_CAP_PER_SESSION || this.deps.proposals.pendingCount() >= PENDING_CAP_TOTAL) {
      return {
        applied: false,
        refused: "proposal-cap",
        problems: [`too many changes are already waiting for the user (at most ${PENDING_CAP_PER_SESSION} per session, ${PENDING_CAP_TOTAL} in all); ask them to review the Approvals page of the Mandu dashboard first`],
      };
    }
    const p = this.deps.proposals.file({
      edits, reason, requestedBy, sessionKey,
      relaxes: ev.delta.relaxations, tightens: ev.delta.tightenings,
      editsHash, lawHash: hashOf(before ?? {}),
      ...(basedOn.length > 0 ? { basedOn } : {}),
    });
    return { applied: false, proposalId: p.id, relaxes: p.relaxes, why: ev.tightening ? "tightening-cap" : "relaxes" };
  }

  /** §5.2: what `edits` would do to the law in force; nothing is written. */
  preview(edits: unknown): PolicyPreviewResult {
    const before = { specId: this.specId(), document: this.deps.docs.document };
    const ev = evaluateEdits(before, edits, { now: this.now() });
    if (!ev.ok) return { ok: false, problems: ev.problems };
    const perEdit = (edits as unknown[]).map((e) => {
      const one = evaluateEdits(before, [e], { now: this.now() });
      return { loosens: !one.ok || !one.tightening };
    });
    return { ok: true, relaxations: ev.delta.relaxations, tightenings: ev.delta.tightenings, perEdit };
  }

  /** Proposals only by default: suggestions have their own read
   *  (`policySuggestions`, plan 14 §5.2) and their own card. */
  proposalsList(status?: PolicyProposal["status"], channel: "admin" | "data" = "admin", kind: PolicyProposal["kind"] = "proposal"): { proposals: PolicyProposalWire[] } {
    this.retireSatisfied();
    return { proposals: this.deps.proposals.listProposals({ kind, ...(status ? { status } : {}) }).map((p) => proposalWire(p, channel)) };
  }

  changesList(limit?: number): PolicyChangesResult {
    const n = typeof limit === "number" && limit > 0 ? Math.min(limit, 500) : 100;
    // Who asked, and which rules each change wrote as the Rules page names
    // them, checked against the law in force (dashboard.md §4.25i).
    const doc = this.deps.docs.document;
    const lists = doc?.lists ?? {};
    return {
      changes: this.deps.proposals.listChanges(n).map((c) => ({
        ...changeWire(c),
        proposedBy: c.proposalId ? this.deps.proposals.getProposal(c.proposalId)?.requestedBy ?? null : null,
        rules: itemStates(doc, c.revert).map((it) => ({
          rowIds: panelRowIds(it.section, it.key, it.after ?? it.before, lists),
          added: it.before === null,
          removed: it.after === null,
          current: it.current,
        })),
      })),
    };
  }

  /** ADMIN: a human's verdict on a proposal. Afterwards, what the new law
   *  already says is closed (`retireSatisfied`). */
  resolve(proposalId: string, verdict: "approved" | "denied", by: string): ResolvePolicyProposalResult {
    try {
      return this.resolveOne(proposalId, verdict, by);
    } finally {
      this.retireSatisfied();
    }
  }

  private resolveOne(proposalId: string, verdict: "approved" | "denied", by: string): ResolvePolicyProposalResult {
    const p = this.deps.proposals.getProposal(proposalId);
    if (!p) throw new OpError(`unknown policy proposal: ${proposalId}`);
    if (p.status !== "pending") throw new OpError(`policy proposal ${proposalId} is already ${p.status}`);
    if (p.kind === "suggestion") {
      if (!this.deps.resolveSuggestion) throw new OpError(`policy suggestion ${proposalId} cannot be resolved here`);
      return this.deps.resolveSuggestion(proposalId, verdict, by);
    }
    if (p.diskHash !== null) return this.resolveDisk(p as PolicyProposal & { diskHash: string }, verdict, by);
    if (verdict === "denied") {
      return { proposal: proposalWire(this.deps.proposals.resolveProposal(p.id, "denied", by)!) };
    }
    const before = this.deps.docs.document;
    // §8.4.6 "An item-level version": an item the proposal was built from
    // changed since it was filed. Approving would overwrite that change
    // with what was read before it, so the proposal is closed and nothing
    // is written; the person reads the item again and decides afresh.
    const stale = movedSince(before, p.basedOn);
    if (stale.length > 0) {
      const closed = this.deps.proposals.resolveProposal(p.id, "superseded", STALE_RESOLVER)!;
      this.deps.docs.log(`policy proposal ${p.id} was built from ${stale.join(", ")} as it was, which changed since; closed, nothing changed`);
      return { proposal: proposalWire(closed), stale };
    }
    const ev = evaluateEdits({ specId: this.specId(), document: before }, p.edits, { by: p.requestedBy, now: this.now() });
    if (!ev.ok) throw new OpError(`policy proposal ${proposalId} no longer applies to the law in force: ${ev.problems.join("; ")}`);
    // The skew guard (§4.5): the law moved and approving would now give up MORE
    // than the human was shown ⇒ re-file, never apply.
    const shown = deltaKeys(p.relaxes);
    const grew = ev.delta.relaxations.some((r) => !shown.has(`${r.facet}\0${r.subject}`));
    if (grew) {
      const next = this.deps.proposals.file({
        edits: p.edits, reason: p.reason, requestedBy: p.requestedBy, sessionKey: p.sessionKey,
        relaxes: ev.delta.relaxations, tightens: ev.delta.tightenings,
        editsHash: p.editsHash, lawHash: hashOf(before ?? {}),
        ...(p.basedOn && p.basedOn.length > 0 ? { basedOn: p.basedOn } : {}),
      });
      const old = this.deps.proposals.resolveProposal(p.id, "superseded", by, { supersededBy: next.id })!;
      return { proposal: proposalWire(old), refiled: proposalWire(next) };
    }
    let change: PolicyChangeRecord;
    try {
      change = this.enact(before, ev.document, {
        via: "proposal", requestedBy: by, sessionKey: p.sessionKey, edits: p.edits,
        delta: [...ev.delta.relaxations, ...ev.delta.tightenings], proposalId: p.id,
      }, `${by} approved ${p.id} from ${p.requestedBy}`);
    } catch (err) {
      if (err instanceof StalePolicyError) throw new OpError(`${err.message} (the proposal is still pending)`);
      throw err;
    }
    const resolved = this.deps.proposals.resolveProposal(p.id, "approved", by, { changeId: change.id })!;
    return { proposal: proposalWire(resolved), changeId: change.id };
  }

  /** ADMIN: revert one recorded change, item by item. */
  undo(changeId: string, by: string): UndoPolicyChangeResult {
    try {
      return this.undoOne(changeId, by);
    } finally {
      this.retireSatisfied();
    }
  }

  private undoOne(changeId: string, by: string): UndoPolicyChangeResult {
    const c = this.deps.proposals.getChange(changeId);
    if (!c) throw new OpError(`unknown policy change: ${changeId}`);
    if (c.via === "undo") throw new OpError(`${changeId} is itself an undo; change the rule directly instead`);
    if (c.via === "disk") throw new OpError(`${changeId} is a hand edit of policy.yaml; change the file directly instead`);
    // The rows it moved are gone from mandu.db: undoing the file half alone
    // would drop those rules, a loosening nobody asked for.
    if (c.via === "move-labels") throw new OpError(`${changeId} moved rules made on the dashboard into policy.yaml without changing them; change the rules directly instead`);
    if (c.undoneAt !== null) throw new OpError(`${changeId} was already undone by ${c.undoneBy}`);
    const before = this.deps.docs.document;
    const conflicts = revertConflicts(before, c.revert);
    if (conflicts.length > 0) {
      throw new OpError(`cannot undo ${changeId}: changed again since (${conflicts.join(", ")}); nothing was changed`);
    }
    const r = revertItems(before, c.revert);
    if (!r.ok) throw new OpError(`cannot undo ${changeId}: the result would be invalid (${r.problems.join("; ")})`);
    const delta = policyDelta(
      compilePolicy({ specId: this.specId(), document: before }),
      compilePolicy({ specId: this.specId(), document: r.document }),
      { now: this.now() },
    );
    const all = [...delta.relaxations, ...delta.tightenings];
    // While a hand edit waits in Approvals, the same revert is made to it
    // (tour item 17), unless it changed one of the same items.
    let heldConflicts: string[] = [];
    const layer = (held: PolicyFileConfig | null): PolicyFileConfig | null => {
      heldConflicts = revertConflicts(held, c.revert);
      if (heldConflicts.length > 0) return null;
      const h = revertItems(held, c.revert);
      return h.ok ? h.document : null;
    };
    let rec: PolicyChangeRecord;
    try {
      rec = this.enact(before, r.document, { via: "undo", requestedBy: by, sessionKey: null, edits: [], delta: all, proposalId: null }, `${by} undid ${changeId}`, layer);
    } catch (err) {
      if (err instanceof StalePolicyError && err.held && heldConflicts.length > 0) {
        throw new OpError(`cannot undo ${changeId} yet: the change to policy.yaml waiting in Approvals changes the same rule (${heldConflicts.join(", ")}); approve or decline it first, then undo. Nothing was changed`);
      }
      if (err instanceof StalePolicyError) throw new OpError(err.message);
      throw err;
    }
    this.deps.proposals.markUndone(c.id, rec.id);
    return { changeId: rec.id, undone: c.id, delta: all };
  }

  /** §4.4: the law as bounded tokens only. The "agent" audience (T-LLM, via
   *  the policy tools) also drops what a page could have chosen: the hosts
   *  of pending asks (a count remains) and other sessions' proposals. */
  explain(opts: { audience?: "agent" | "assistant"; sessionKey?: string } = {}): PolicyExplainResult {
    this.retireSatisfied();
    const forAgent = opts.audience === "agent";
    const ownKey = typeof opts.sessionKey === "string" && SESSION_KEY.test(opts.sessionKey) ? opts.sessionKey : null;
    const law = getCurrentPolicy();
    const t = token;
    const tl = (l: readonly string[]) => l.map(t);
    const locks: PolicyExplainResult["locks"] = [];
    for (const l of law.pathLabels.values()) {
      locks.push({ path: t(l.path), level: l.confidentiality, recursive: l.recursive, pattern: !!l.glob, bindings: tl(l.bindings), source: "policy-file" });
    }
    for (const l of this.deps.dbLabels()) {
      if (law.pathLabels.has(l.path)) continue;
      locks.push({ path: t(l.path), level: l.confidentiality, recursive: l.recursive, pattern: !!l.glob, bindings: tl(l.bindings), source: "dashboard" });
    }
    const inbound = expandListsInDocument(law.document)?.inbound;
    const origins = {} as PolicyExplainResult["origins"];
    for (const cat of ["url", "channel", "dir"] as const) {
      origins[cat] = { trusted: tl(inbound?.[cat]?.trustedList ?? []), untrusted: tl(inbound?.[cat]?.untrustedList ?? []) };
    }
    const asks = new Map<string, number>();
    let askCount = 0;
    for (const a of this.deps.pendingAsks()) {
      askCount += a.count;
      const h = t(this.deps.hostOf(a.destination));
      asks.set(h, (asks.get(h) ?? 0) + a.count);
    }
    const hits: Record<string, number> = {};
    for (const [id, row] of Object.entries(this.deps.ruleHits())) hits[t(id)] = row.hits;
    return {
      specId: law.specId,
      lawSource: law.lawSource.kind,
      locks,
      userRules: law.userRules.map((r) => ({ id: t(r.id), mode: r.mode, from: r.from ? tl(r.from) : null, to: tl(r.to), expiresAt: r.expiresAt })),
      dispositions: Object.fromEntries(Object.entries(law.dispositions).map(([k, v]) => [t(k), v])),
      origins,
      connectAllow: tl(connectAllowSpecs(law)),
      relaxations: relaxationsOf(law).map((r) => ({ kind: r.kind, subject: t(r.subject) })),
      pendingProposals: this.deps.proposals.listProposals({ status: "pending", kind: "proposal" })
        .filter((p) => !forAgent || (ownKey !== null && p.sessionKey === ownKey))
        .map((p) => ({
        id: p.id,
        requestedBy: t(p.requestedBy),
        createdAt: p.createdAt,
        relaxes: p.relaxes.map((r) => ({ facet: r.facet, subject: t(r.subject) })),
      })),
      pendingAsks: forAgent ? [] : [...asks].map(([destinationHost, count]) => ({ destinationHost, count })),
      pendingAskCount: askCount,
      ruleHits: hits,
      // Read-only: a model is added, changed or removed in Settings › Models
      // or policy.yaml (every such change is a relaxation, §3.2).
      models: law.models.map(explainModel),
    };
  }
}
