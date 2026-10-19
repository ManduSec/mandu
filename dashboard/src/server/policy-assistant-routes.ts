/**
 * server/policy-assistant-routes — "Describe what you want"
 * (policy-surface.md §8.5.2; dashboard.md §4.25):
 *
 *   POST /api/policy/assistant        { sentence }         → a Suggestion (rows, loosens, note, edits, expected)
 *   POST /api/policy/assistant/apply  { edits, expected }  → { applied: true, changeId }
 *   POST /api/policy/assistant/try    { edits, index }     → { now: Part[], after: Part[] }
 *        "Try it" on one row: the arbiter's Test a flow for that row's website or
 *        release, against the law in force and against the law WITH the whole
 *        suggestion (`testFlow` `withEdits`, nothing written).
 *
 * Both are behind the server's global mutating gate (CSRF + admin session):
 * the first spends the person's model budget, the second changes the law.
 *
 * Suggest: policy-assistant.ts (a quarantined model call; 503 `unconfigured`
 * when there is no channel, never a guess; 422 when the answer is not a valid
 * rule change).
 *
 * Apply is the HUMAN's act, and it is bound to what the person was shown:
 *   1. re-preview the edits against the law in force; if applying would now
 *      loosen anything not in `expected`, refuse (409, "describe it again");
 *   2. `policyPropose` on the ADMIN channel (requestedBy "assistant"): a pure
 *      tightening applies there and then;
 *   3. otherwise the proposal it filed is approved at once by this click
 *      (`resolvePolicyProposal`, "human:dashboard"); if the arbiter's own skew
 *      guard re-files it (the law moved in between), the re-filed proposal is
 *      denied and the answer is 409, so nothing the person did not see is
 *      ever applied.
 * Either way the change is recorded, shows in History, and can be undone.
 *
 * Apply refuses (422) a list carrying a model-endpoint op before anything is
 * previewed or proposed: models change only in Settings › Models or by hand
 * (policy-surface.md §8.4.3a), and the arbiter refuses the op again for
 * requestedBy "assistant".
 */
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import {
  AssistantAnswerError,
  AssistantUnconfiguredError,
  MODELS_ELSEWHERE,
  modelEditProblems,
  relaxKey,
  suggestRules,
  tryLine,
  tryProbe,
  SENTENCE_MAX,
  type AssistantArbiter,
  type AssistantModel,
} from "../policy-assistant.js";
import type { PolicyProposalArbiter } from "./policy-proposal-routes.js";

type ProposeAnswer =
  | { applied: true; changeId: string | null }
  | { applied: false; proposalId: string; relaxes: Array<{ facet: string; subject: string }> }
  | { applied: false; refused: string; problems: string[]; changed?: string[] };

/** One item of the law and the version it had when read (the arbiter's
 *  `policyDocument.itemVersions`, the snapshot's `modelVersions`;
 *  policy-surface.md §8.4.6 "An item-level version"). */
export interface ItemVersion {
  section: string;
  key: string;
  version: string;
}

/** The narrow arbiter surface (reads on the data socket; propose/resolve on
 *  the admin channel). Optional: an arbiter predating stage C answers 501. */
export interface PolicyAssistantArbiter extends Partial<AssistantArbiter>, PolicyProposalArbiter {
  testFlow?(req: { source?: { tool?: string; origin?: string }; destination?: string; boundary?: "network"; withEdits?: unknown }): Promise<unknown>;
  policyPropose?(req: { edits: unknown; reason?: string; requestedBy?: string; basedOn?: ItemVersion[] }): Promise<ProposeAnswer>;
}

const UNSUPPORTED = "this arbiter has no rule assistant ops — restart the Mandu stack on the current build";
const APPLY_REASON = "Applied from the dashboard's Describe what you want box";

function hasReads(a: PolicyAssistantArbiter): a is PolicyAssistantArbiter & AssistantArbiter {
  return !!(a.policyExplain && a.policySchema && a.policyPreview);
}

/** `home`: the server's home folder, so the suggestion's rows name a file
 *  under it `~/…` (dashboard.md §4.34), as the Rules page does. */
export async function postSuggest(
  arbiter: PolicyAssistantArbiter,
  model: () => Promise<AssistantModel>,
  req: IncomingMessage,
  res: ServerResponse,
  home?: string,
): Promise<void> {
  if (!hasReads(arbiter)) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { sentence?: unknown } | undefined;
  const sentence = typeof body?.sentence === "string" ? body.sentence : "";
  if (sentence.trim() === "" || sentence.length > SENTENCE_MAX) {
    return json(res, 400, { error: `describe what you want in 1 to ${SENTENCE_MAX} characters` });
  }
  try {
    json(res, 200, await suggestRules({ arbiter, model, home }, sentence));
  } catch (err) {
    if (err instanceof AssistantUnconfiguredError) {
      return json(res, 503, { error: `No assistant model is set up: ${err.message}`, unconfigured: true });
    }
    if (err instanceof AssistantAnswerError) return json(res, 422, { error: err.message, problems: err.problems });
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
  }
}

export async function postApply(arbiter: PolicyAssistantArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.policyPreview || !arbiter.policyPropose || !arbiter.resolvePolicyProposal) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { edits?: unknown; expected?: unknown } | undefined;
  const edits = body?.edits;
  const expected = body?.expected;
  if (!Array.isArray(edits) || edits.length === 0 || !Array.isArray(expected) || !expected.every((k) => typeof k === "string")) {
    return json(res, 400, { error: "body must be { edits: [...], expected: [...] } from a suggestion" });
  }
  const modelEdits = modelEditProblems(edits);
  if (modelEdits.length > 0) return json(res, 422, { error: MODELS_ELSEWHERE, problems: modelEdits });
  const MOVED = "The rules changed since this suggestion was made, and applying it now would loosen protection in a way you were not shown. Describe it again.";
  const r = await applyAsHuman(arbiter, edits, expected as string[], { reason: APPLY_REASON, requestedBy: "assistant", approver: "human:dashboard", moved: MOVED });
  json(res, r.status, r.body);
}

/** The human-apply sequence shared by the Describe box and the Rules page's
 *  row buttons (dashboard.md §4.25c): preview, refuse a loosening not in
 *  `expected`, propose on the admin channel, approve at once as `approver`,
 *  and deny whatever the skew guard re-files. Returns the HTTP answer.
 *
 *  `basedOn` (policy-surface.md §8.4.6 "An item-level version"): the items
 *  the edits carry fields over from, with the versions read. The arbiter
 *  refuses the propose, or the approval, once one of them changed: 409
 *  `{ stale: true, changed }` with `opts.stale` as the words, nothing
 *  written. */
export async function applyAsHuman(
  arbiter: PolicyAssistantArbiter,
  edits: unknown[],
  expected: readonly string[],
  opts: { reason: string; requestedBy: string; approver: string; moved: string; basedOn?: ItemVersion[]; stale?: string },
): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!arbiter.policyPreview || !arbiter.policyPropose || !arbiter.resolvePolicyProposal) return { status: 501, body: { error: UNSUPPORTED } };
  const shown = new Set(expected);
  const grew = (rs: ReadonlyArray<{ facet: string; subject: string }>): boolean => rs.some((r) => !shown.has(relaxKey(r)));
  try {
    const preview = await arbiter.policyPreview(edits);
    if (!preview.ok) return { status: 422, body: { error: "this is not a valid rule change any more", problems: preview.problems } };
    if (grew(preview.relaxations)) return { status: 409, body: { error: opts.moved } };

    const basedOn = opts.basedOn ?? [];
    const r = await arbiter.policyPropose({ edits, reason: opts.reason, requestedBy: opts.requestedBy, ...(basedOn.length > 0 ? { basedOn } : {}) });
    if (r.applied) return { status: 200, body: { applied: true, changeId: r.changeId } };
    if ("refused" in r && r.refused === "stale" && Array.isArray(r.changed) && r.changed.length > 0) {
      return { status: 409, body: { error: opts.stale ?? opts.moved, stale: true, changed: r.changed } };
    }
    if ("refused" in r) {
      return { status: r.refused === "invalid" ? 422 : 409, body: { error: `Not applied (${r.refused}): ${r.problems.join("; ")}` } };
    }
    if (grew(r.relaxes)) {
      await arbiter.resolvePolicyProposal(r.proposalId, "denied", opts.approver);
      return { status: 409, body: { error: opts.moved } };
    }
    const resolved = await arbiter.resolvePolicyProposal(r.proposalId, "approved", opts.approver);
    // Closed by the arbiter: an item it was built from changed meanwhile.
    if (Array.isArray(resolved.stale) && resolved.stale.length > 0) {
      return { status: 409, body: { error: opts.stale ?? opts.moved, stale: true, changed: resolved.stale } };
    }
    if (resolved.refiled) {
      await arbiter.resolvePolicyProposal(resolved.refiled.id, "denied", opts.approver);
      return { status: 409, body: { error: opts.moved } };
    }
    return { status: 200, body: { applied: true, changeId: resolved.changeId ?? null } };
  } catch (err) {
    if (isAdminBoundaryError(err)) return { status: 503, body: { error: String((err as Error).message) } };
    const msg = String((err as Error)?.message ?? err);
    return { status: /already|no longer applies|changed on disk/.test(msg) ? 409 : 502, body: { error: msg } };
  }
}

export async function postTry(arbiter: PolicyAssistantArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.testFlow) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { edits?: unknown; index?: unknown } | undefined;
  const edits = body?.edits;
  const index = body?.index;
  if (!Array.isArray(edits) || typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= edits.length) {
    return json(res, 400, { error: "body must be { edits: [...], index } from a suggestion" });
  }
  const probe = tryProbe(edits[index]);
  if (!probe) return json(res, 400, { error: "this row is not about a website or a release, so there is nothing to try" });
  try {
    const [now, after] = await Promise.all([arbiter.testFlow(probe), arbiter.testFlow({ ...probe, withEdits: edits })]);
    json(res, 200, { now: tryLine(edits[index], now), after: tryLine(edits[index], after) });
  } catch (err) {
    const msg = String((err as Error)?.message ?? err);
    json(res, /withEdits/.test(msg) ? 422 : isAdminBoundaryError(err) ? 503 : 502, { error: msg });
  }
}
