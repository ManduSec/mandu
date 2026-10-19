/**
 * server/approval-routes — the interactive egress-approval queue routes
 * (`/api/egress/approvals*`) and the narrow arbiter surface they depend on
 * (extracted VERBATIM from src/server.ts in the server.ts decomposition; see
 * server.ts for the route map and security posture). The dashboard only renders
 * the queue and routes a human verdict; it never mutates the store itself.
 */

import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import type { HolderSourceWire } from "../policy-model.js";
import { applyAsHuman, type ItemVersion, type PolicyAssistantArbiter } from "./policy-assistant-routes.js";
import { relaxKey } from "../policy-assistant.js";

/**
 * A single queued egress-approval entry. Mirrors arbiter/policy/egress-approvals.ts
 * `EgressApproval` EXACTLY (the dashboard package typechecks standalone, so the
 * shape is declared here rather than imported from the sibling arbiter package —
 * same decoupling rationale as anthropic-proxy's arbiter-client.ts). The dashboard
 * only renders these and routes a human verdict; it never mutates the store.
 */
export interface EgressApproval {
  id: string;
  symbol: string;
  destination: string;
  status: "pending" | "approved" | "denied";
  reason: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
  /** Epoch millis of the human resolution; null/absent while pending or for
   * pre-column rows (policy-surface.md §9.6). */
  resolvedAt?: number | null;
  /** Distinct session keys that created/bumped this entry (most-recent-last,
   * arbiter-capped) — absent on old arbiters / pre-column rows. */
  sessions?: string[];
  /** Verdict scope (policy-surface.md §9.8.7): "always" = standing (the
   * default), "once" = spent by one gated decision. Absent on a pre-scope
   * arbiter, which only ever had standing verdicts. */
  scope?: ApprovalScope;
  /** Epoch millis a once-scoped verdict was spent, or null/absent. */
  consumedAt?: number | null;
  /** A waiting prompt hold under a locked administrator's `ask` row (plan 15
   * §12, 2026-10-04): this message only; an Always is refused (409). */
  onceOnly?: boolean;
  /** An answered verdict about a program that applies to nothing any more
   * (arbiter flow-taint.ts `verdictNoLongerApplies`), attached at read time. */
  noLongerApplies?: "name-only" | "printer" | "interpreter" | "unvetted";
  /** A HIGH session's ask: what that session read (confidentiality.md §4,
   * 2026-10-11); symbols and origins only, never a value. */
  sessionReads?: Array<{ symbol: string; origin: string | null }>;
  sessionReadsMore?: number;
  /** A HIGH session's command ask: held by the guard, and its hosts. */
  sessionConfined?: boolean;
  sessionBindings?: string[];
  /** A HIGH session's network ask whose latest request was a HELD
   * command's connection (confidentiality.md §4, "A held command's refused
   * connection", 2026-10-12): the card says the command's request was
   * stopped and Allow once lets the next try through. */
  sessionHeld?: boolean;
  /** A FILE's card (egress-hold.md "One card per file", 2026-10-19): how
   * many protected values of the file its answer covers; attached by the
   * arbiter at read time, two or more. Absent otherwise. */
  fileValues?: number;
  /** A holder's send question (`holder-send:` rows, confidentiality plan
   * 13 §5.4, 2026-10-11): every file the holding program holds as it stands
   * now, where each may go, whether it blocks the destination and whether
   * an *Always* can add the destination to its rule; attached by the arbiter
   * at read time to a pending row. Paths and hosts, never a value. Absent on
   * any other row and on older arbiters. */
  holderSources?: HolderSourceWire[];
  /** "Send without it" (confidentiality.md §4): a once denial whose one use
   * sends the request with a marker where the secret was. */
  strip?: boolean;
  /** Whether a waiting card takes "Send without it" (the arbiter's read-time
   * mark: a secret's placeholder in a request to a host). Only there is the
   * button offered; the arbiter refuses the answer anywhere else. */
  stripOffered?: boolean;
}

/** Lifecycle filter for {@link ApprovalsArbiter.egressApprovals}. */
export type ApprovalStatus = EgressApproval["status"];

/** How long a verdict stands: forever ("always") or for one use ("once"). */
export type ApprovalScope = "once" | "always";

/**
 * The NARROW arbiter surface the egress-approval routes depend on (the arbiter-
 * client pattern — see anthropic-proxy/src/arbiter-client.ts). server-main wires the
 * real arbiter IPC client behind this; the tests inject an in-memory fake. Kept
 * deliberately tiny so the dashboard package never drags arbiter/**.ts into its
 * tsc rootDir.
 */
export interface ApprovalsArbiter {
  /** List queued egress-approval entries, optionally filtered by status. */
  egressApprovals(status?: ApprovalStatus): Promise<EgressApproval[]>;
  /** Apply a human verdict by entry id: approve:true → approved, false → denied.
   *  `scope` "once" arms a single-use verdict (absent → standing "always"; a
   *  pre-scope arbiter ignores the extra wire field, which is the honest
   *  degrade — the verdict lands, standing). Rejects (throws) if `approvalId`
   *  is unknown. */
  resolveEgressApproval(
    approvalId: string,
    approve: boolean,
    scope?: ApprovalScope,
    /** `strip` (with `approve: false`): "Send without it" (dashboard.md
     *  §4.34). Rejects when the arbiter refuses it on this card. */
    opts?: { strip?: boolean },
  ): Promise<EgressApproval>;
  /** Forget a human verdict by id (dashboard.md §4.25c): the pair is asked
   *  again on its next attempt. Optional: an arbiter predating the op → 501.
   *  Rejects for an unknown or still-pending id. */
  forgetEgressApproval?(approvalId: string): Promise<EgressApproval>;
  /** Plan 13 §5.4, §9 R2: the policy edit an *Always* on one file of a
   *  holder's send question files (a READ: the route applies it on the
   *  admin channel, `applyAsHuman`). Optional: an arbiter predating it → 501.
   *  Rejects when the file takes no *Always* (not one of the row's, already
   *  bound, a folder rule, …), with the arbiter's reason. */
  holderSourceBinding?(approvalId: string, path: string): Promise<{ edits: unknown[]; rule: string; relaxes: Array<{ facet: string; subject: string }>; basedOn?: ItemVersion[] }>;
}

export function arbiterDisabled(res: ServerResponse): void {
  json(res, 404, { error: "arbiter not connected" });
}

/** GET /api/egress/approvals[?status=pending|approved|denied] → { approvals }. */
export async function listApprovals(
  arbiter: ApprovalsArbiter,
  url: string,
  res: ServerResponse,
): Promise<void> {
  const params = new URLSearchParams(url.split("?")[1] ?? "");
  const statusRaw = params.get("status");
  const status =
    statusRaw === "pending" || statusRaw === "approved" || statusRaw === "denied"
      ? statusRaw
      : undefined;
  try {
    const approvals = await arbiter.egressApprovals(status);
    json(res, 200, { approvals });
  } catch (err) {
    json(res, 503, { error: String((err as Error)?.message ?? err) });
  }
}

/** POST /api/egress/approvals/<id>/{approve,approve-once,deny,send-without} → { approval }.
 *  Unknown id → 404 (the arbiter rejects, which we surface as not-found).
 *  `send-without` ("Send without it", dashboard.md §4.34) on a card that
 *  does not take it → 409 with the arbiter's reason. */
export async function resolveApproval(
  arbiter: ApprovalsArbiter,
  approvalId: string,
  approve: boolean,
  res: ServerResponse,
  scope?: ApprovalScope,
  opts?: { strip?: boolean },
): Promise<void> {
  try {
    const approval = opts?.strip === true
      ? await arbiter.resolveEgressApproval(approvalId, false, "once", { strip: true })
      : await arbiter.resolveEgressApproval(approvalId, approve, scope);
    json(res, 200, { approval });
  } catch (err) {
    // No admin channel (adopted arbiter) / refused on the data socket → 503:
    // the stack's state, not this id. A question no answer can make take
    // effect (filed before printers or bare interpreters stopped being
    // readers, plan 13 D8) → 409 with the arbiter's reason, as is an Always
    // on a held message under a locked administrator's `ask` row (plan 15
    // §12, 2026-10-04: this message only). Everything else the arbiter
    // rejects is an unknown id → 404.
    const msg = String((err as Error)?.message ?? err);
    const status = isAdminBoundaryError(err) ? 503 : /no longer applies|answer it for this message only|Send without it/.test(msg) ? 409 : 404;
    json(res, status, { error: msg, approvalId });
  }
}

/** POST /api/egress/approvals/<id>/forget → { approval } (the entry as it was).
 *  Pending → 409 (it is still waiting for an answer); unknown → 404. */
export async function forgetApproval(
  arbiter: ApprovalsArbiter,
  approvalId: string,
  res: ServerResponse,
): Promise<void> {
  if (!arbiter.forgetEgressApproval) {
    json(res, 501, { error: "this Mandu service cannot forget an answer; restart the Mandu stack on the current build" });
    return;
  }
  try {
    const approval = await arbiter.forgetEgressApproval(approvalId);
    json(res, 200, { approval });
  } catch (err) {
    const msg = String((err as Error)?.message ?? err);
    const status = isAdminBoundaryError(err) ? 503 : /still waiting/.test(msg) ? 409 : 404;
    json(res, status, { error: msg, approvalId });
  }
}

/** Said when the file's rule changed between the plan and the write. */
export const ALWAYS_STALE = "This file's rule was changed somewhere else just now, so nothing was changed. Press Always again to add this place to the rule as it is now.";

/** POST /api/egress/approvals/<id>/always-source {path} → { applied, changeId,
 *  released, left } (confidentiality plan 13 §5.4, §9 R2; dashboard.md §4.34
 *  "A send names every file"). One *Always* of a holder's send question: the
 *  arbiter names the edit (that file's rule gains the destination), and it is
 *  applied as the person's own loosening on the admin channel, the Rules
 *  page's path (`applyAsHuman`: previewed, refused if it would loosen any
 *  rule but that file's, proposed and approved at once). Then the queue is
 *  read again: `released` when the question is gone (every file may go
 *  there now, so the next send goes), else `left`, the files still in the
 *  way. Never a verdict on the row, never another file's rule.
 *
 *  The arbiter plans the edit from its own read of the law, carrying the
 *  file's level and hosts over, and names the rules it read with their
 *  versions (`basedOn`, policy-surface.md §8.4.6 "An item-level version"):
 *  they go with the proposal, so a change to that file's rule (or to the
 *  rule that decided its label) landing between the plan and the write
 *  refuses it, 409 `stale`, nothing written. */
export async function alwaysSource(
  arbiter: ApprovalsArbiter,
  policyDoc: PolicyAssistantArbiter | undefined,
  approvalId: string,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const UNSUPPORTED = "this Mandu service cannot change a file's rule from Approvals; restart the Mandu stack on the current build";
  if (!arbiter.holderSourceBinding || !policyDoc?.policyPreview || !policyDoc.policyPropose || !policyDoc.resolvePolicyProposal) {
    json(res, 501, { error: UNSUPPORTED });
    return;
  }
  const body = await readJson(req);
  const path = body && typeof body === "object" && typeof (body as { path?: unknown }).path === "string" ? (body as { path: string }).path : "";
  if (path === "") {
    json(res, 400, { error: "body must be { path } naming one file of the question" });
    return;
  }
  let planned: { edits: unknown[]; rule: string; relaxes: Array<{ facet: string; subject: string }>; basedOn?: ItemVersion[] };
  try {
    planned = await arbiter.holderSourceBinding(approvalId, path);
  } catch (err) {
    const msg = String((err as Error)?.message ?? err);
    json(res, isAdminBoundaryError(err) ? 503 : /no longer applies|may already go/.test(msg) ? 409 : 422, { error: msg, approvalId });
    return;
  }
  const r = await applyAsHuman(policyDoc, planned.edits, planned.relaxes.map(relaxKey), {
    reason: `Always, from Approvals: a program's send (${approvalId})`,
    requestedBy: "approvals-page",
    approver: "human:dashboard",
    moved: "Your rules changed while you were deciding. Nothing was changed. Try again.",
    ...(Array.isArray(planned.basedOn) && planned.basedOn.length > 0 ? { basedOn: planned.basedOn } : {}),
    stale: ALWAYS_STALE,
  });
  if (r.status !== 200) {
    json(res, r.status, { ...r.body, approvalId });
    return;
  }
  let left: string[] = [];
  let released = true;
  try {
    const row = (await arbiter.egressApprovals("pending")).find((a) => a.id === approvalId);
    if (row) {
      released = false;
      left = (row.holderSources ?? []).filter((s) => s.blocks).map((s) => s.path);
    }
  } catch {
    released = false;
  }
  json(res, 200, { applied: true, changeId: r.body["changeId"] ?? null, rule: planned.rule, released, left });
}
