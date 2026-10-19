/**
 * server/policy-proposal-routes — the policy agent surface's human side
 * (policy-surface.md §8.4.2, §8.6; dashboard.md §4.25):
 *
 *   GET  /api/policy/proposals?status=pending|approved|denied|superseded
 *        → { proposals: ProposalCardVM[] }
 *   POST /api/policy/proposals/<pp-NNNNNN>   { verdict: "approved"|"denied" }
 *        → { proposal: ProposalCardVM, changeId?, refiled?: ProposalCardVM }
 *   GET  /api/policy/changes?limit=N          → { changes: ChangeRowVM[] }
 *   GET  /api/policy/rules/origins            → { origins: {rowId: RuleOriginVM}, complete, unrecorded }
 *   POST /api/policy/changes/<pc-NNNNNN>/undo → { changeId, undone }
 *
 * The GETs are projections (the card grammar, view-model/policy-proposals.ts).
 * They are read without the admin session too (the product page lists them
 * for anyone with the dashboard), so a prompt exception's pattern, which may
 * hold the person's own words, is shown only to a read with the CSRF header
 * AND the admin session (`patterns`, server.ts); any other read gets the row
 * with the pattern hidden and `patternsHidden: true` (plan 15 §13.7 item 4).
 * The listing is otherwise the same. A file a GET's row names under the
 * dashboard's home folder (`home`, the server's) reads `~/…`, as on the
 * Rules page (dashboard.md §4.34 "`~` is the dashboard's home").
 *
 * the POSTs are human decisions: behind the server's global mutating gate
 * (CSRF + admin session) and enacted over the arbiter's ADMIN channel. The
 * arbiter's refusals (unknown id, already resolved, changed again since, the
 * file changed on disk, a change that cannot be made to a held hand edit
 * too) → 409 with its text; an adopted arbiter → 503; an
 * arbiter without the ops → 501.
 */
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import {
  ruleOrigins,
  toChangeRow,
  UNRECORDED_ORIGIN,
  toProposalCard,
  hidePromptPatterns,
  type PolicyChangeRow,
  type PolicyProposalRow,
} from "../view-model/policy-proposals.js";

/** The narrow arbiter surface these routes need (all optional: an arbiter
 *  predating the policy agent surface answers 501). */
export interface PolicyProposalArbiter {
  policyProposals?(status?: PolicyProposalRow["status"]): Promise<{ proposals: PolicyProposalRow[] }>;
  policyChanges?(limit?: number): Promise<{ changes: PolicyChangeRow[] }>;
  resolvePolicyProposal?(proposalId: string, verdict: "approved" | "denied", requestedBy?: string): Promise<{
    proposal: PolicyProposalRow;
    changeId?: string;
    refiled?: PolicyProposalRow;
    /** An item it was built from changed since (§8.4.6 "An item-level
     *  version"): nothing written, the proposal closed. */
    stale?: string[];
  }>;
  undoPolicyChange?(changeId: string, requestedBy?: string): Promise<{ changeId: string; undone: string }>;
}

export const PROPOSAL_ID = /^pp-\d{6}$/;
export const CHANGE_ID = /^pc-\d{6}$/;
const STATUSES = new Set(["pending", "approved", "denied", "superseded"]);
const UNSUPPORTED = "this Mandu service predates rule-change requests; restart the Mandu stack on the current build";
const STALE = "This change was asked for from settings that have changed since, so nothing was changed and it is closed. Make the change again if you still want it.";

function statusFor(err: unknown): number {
  if (isAdminBoundaryError(err)) return 503;
  const msg = String((err as Error)?.message ?? err);
  if (/unknown policy|already|no longer applies|changed again|changed on disk|cannot undo|itself an undo|waits for a human in Approvals/.test(msg)) return 409;
  return 502;
}

function fail(res: ServerResponse, err: unknown): void {
  json(res, statusFor(err), { error: String((err as Error)?.message ?? err) });
}

/** True when a listing hides at least one exception's pattern. */
function anyHidden(rows: ReadonlyArray<{ edits?: unknown }>): boolean {
  return rows.some((r) => Array.isArray(r.edits) && hidePromptPatterns(r.edits).hidden);
}

/** `patterns`: the read carries the CSRF header AND the admin session.
 *  `home`: the dashboard's home folder (none: every path as recorded). */
export async function getProposals(arbiter: PolicyProposalArbiter, url: URL, res: ServerResponse, patterns = true, home = ""): Promise<void> {
  if (!arbiter.policyProposals) return json(res, 501, { error: UNSUPPORTED });
  const status = url.searchParams.get("status");
  if (status !== null && !STATUSES.has(status)) return json(res, 400, { error: "status must be pending | approved | denied | superseded" });
  try {
    const r = await arbiter.policyProposals((status ?? undefined) as PolicyProposalRow["status"] | undefined);
    json(res, 200, {
      proposals: r.proposals.map((p) => toProposalCard(p, { patterns, home })),
      ...(!patterns && anyHidden(r.proposals) ? { patternsHidden: true } : {}),
    });
  } catch (err) {
    fail(res, err);
  }
}

export async function postProposalVerdict(arbiter: PolicyProposalArbiter, id: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.resolvePolicyProposal) return json(res, 501, { error: UNSUPPORTED });
  if (!PROPOSAL_ID.test(id)) return json(res, 400, { error: "not a proposal id" });
  const body = (await readJson(req)) as { verdict?: unknown } | undefined;
  const verdict = body?.verdict;
  if (verdict !== "approved" && verdict !== "denied") return json(res, 400, { error: 'body must be { verdict: "approved" | "denied" }' });
  try {
    const r = await arbiter.resolvePolicyProposal(id, verdict, "dashboard");
    // Built from an earlier read of a setting that changed since
    // (policy-surface.md §8.4.6 "An item-level version"): closed, nothing
    // written; approving it would have overwritten the newer change.
    if (Array.isArray(r.stale) && r.stale.length > 0) {
      return json(res, 409, { error: STALE, stale: true, proposal: toProposalCard(r.proposal) });
    }
    json(res, 200, {
      proposal: toProposalCard(r.proposal),
      ...(r.changeId ? { changeId: r.changeId } : {}),
      ...(r.refiled ? { refiled: toProposalCard(r.refiled) } : {}),
    });
  } catch (err) {
    fail(res, err);
  }
}

export async function getChanges(arbiter: PolicyProposalArbiter, url: URL, res: ServerResponse, patterns = true, home = ""): Promise<void> {
  if (!arbiter.policyChanges) return json(res, 501, { error: UNSUPPORTED });
  const raw = url.searchParams.get("limit");
  const limit = raw === null ? 50 : Number(raw);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) return json(res, 400, { error: "limit must be an integer 1-500" });
  try {
    const r = await arbiter.policyChanges(limit);
    json(res, 200, {
      changes: r.changes.map((ch) => toChangeRow(ch, { patterns, home })),
      ...(!patterns && anyHidden(r.changes) ? { patternsHidden: true } : {}),
    });
  } catch (err) {
    fail(res, err);
  }
}

/** The most changes the origins join reads (the arbiter's own cap). */
export const ORIGINS_LIMIT = 500;

/**
 * GET /api/policy/rules/origins (dashboard.md §4.25i): who put each Rules
 * row's rule there, from the arbiter's change record. `complete` is false
 * when the record holds more changes than were read, so a row missing from
 * `origins` may be older than the window: the page then says nothing rather
 * than "no record".
 */
export async function getRuleOrigins(arbiter: PolicyProposalArbiter, res: ServerResponse): Promise<void> {
  if (!arbiter.policyChanges) return json(res, 501, { error: UNSUPPORTED });
  try {
    const r = await arbiter.policyChanges(ORIGINS_LIMIT);
    // An arbiter predating `rules` names no rows: nothing is known, so
    // nothing may be called "no record" either.
    const joinable = r.changes.every((c) => Array.isArray(c.rules));
    json(res, 200, {
      origins: ruleOrigins(r.changes),
      complete: joinable && r.changes.length < ORIGINS_LIMIT,
      // What a row no recorded change names reads as, when `complete`.
      unrecorded: UNRECORDED_ORIGIN,
    });
  } catch (err) {
    fail(res, err);
  }
}

export async function postUndoChange(arbiter: PolicyProposalArbiter, id: string, res: ServerResponse): Promise<void> {
  if (!arbiter.undoPolicyChange) return json(res, 501, { error: UNSUPPORTED });
  if (!CHANGE_ID.test(id)) return json(res, 400, { error: "not a change id" });
  try {
    const r = await arbiter.undoPolicyChange(id, "dashboard");
    json(res, 200, { changeId: r.changeId, undone: r.undone });
  } catch (err) {
    fail(res, err);
  }
}
