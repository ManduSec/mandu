/**
 * server/rule-action-routes — the Rules page's row buttons (dashboard.md §4.25c):
 *
 *   POST /api/policy/rules/change { id, action, expected? }
 *        → { applied: true, changeId }                 done (undo from the answer)
 *        → { applied: false, confirm: true, expected } it would loosen protection:
 *                                                      ask the person, then send
 *                                                      the same body with `expected`
 *
 * The browser names a row and an action; the edit is planned HERE from the
 * raw law in force (rule-actions.ts), never taken from the request. A change
 * that only tightens applies at once. One that loosens needs a second request
 * carrying the loosenings the person confirmed, and it goes through the same
 * human-apply sequence as the Describe box (applyAsHuman): if the law moved and
 * the change would now loosen more than was confirmed, nothing is applied.
 * Every change is recorded and can be undone.
 *
 * Allow / Block on a rule of your own rewrites the rule whole (`release` by
 * id), carrying its `from` and `expires` over from the read above; it names
 * the rule with the version that read found (`basedOn`, policy-surface.md
 * §8.4.6 "An item-level version"), so a change to the same rule landing
 * between the read and the write refuses it (409 `stale`) instead of being
 * overwritten.
 *
 * Behind the server's global mutating gate (CSRF + admin session) like every
 * other policy write.
 */
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import { applyAsHuman } from "./policy-assistant-routes.js";
import type { PolicyDocArbiter } from "./policy-doc-routes.js";
import { relaxKey } from "../policy-assistant.js";
import { planRuleAction, type RuleAction } from "../rule-actions.js";
import { locateRule } from "../rule-source.js";

/** The approver the arbiter records; History reads it back (policy-proposals.ts). */
export const RULES_PAGE_APPROVER = "human:rules-page";

const UNSUPPORTED = "this Mandu service cannot change rules from this page; restart the Mandu stack on the current build";
const MOVED = "Your rules changed while you were deciding. Nothing was changed. Try again.";
const STALE = "This rule was changed somewhere else just now, so nothing was changed. Reload the page to see it as it is, then try again.";

export async function postRuleChange(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.policyPreview || !arbiter.policyPropose || !arbiter.resolvePolicyProposal) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { id?: unknown; action?: unknown; expected?: unknown } | undefined;
  const id = typeof body?.id === "string" ? body.id : "";
  const action = body?.action as RuleAction;
  const expected = body?.expected;
  if (expected !== undefined && (!Array.isArray(expected) || !expected.every((k) => typeof k === "string"))) {
    return json(res, 400, { error: "expected must be the list this route answered with" });
  }
  let inForce: unknown;
  let ruleVersions: Record<string, string> | undefined;
  try {
    const pd = await arbiter.policyDocument();
    inForce = pd.inForce;
    ruleVersions = pd.itemVersions?.["user_rules"];
  } catch (err) {
    return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
  }
  const plan = planRuleAction(inForce, id, action);
  if (!plan.ok) return json(res, plan.status, { error: plan.error });

  if (expected === undefined) {
    let preview;
    try {
      preview = await arbiter.policyPreview(plan.edits);
    } catch (err) {
      return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
    }
    if (!preview.ok) {
      const gone = preview.problems.some((p) => /\bno (lock on|user rule|destination rule)\b/.test(p));
      return json(res, gone ? 409 : 422, gone ? { error: "This rule is no longer in your rules. Reload the page." } : { error: "this change is not valid", problems: preview.problems });
    }
    if (preview.relaxations.length > 0) {
      return json(res, 200, { applied: false, confirm: true, expected: preview.relaxations.map(relaxKey) });
    }
  }
  // A rule rewritten whole names the version it was read at (an older
  // arbiter answers none, and is sent none).
  const basedOn = plan.edits.flatMap((e) => {
    const id = e["op"] === "release" && typeof e["id"] === "string" ? e["id"] : null;
    const version = id !== null ? ruleVersions?.[id] : undefined;
    return id !== null && version ? [{ section: "user_rules", key: id, version }] : [];
  });
  const r = await applyAsHuman(arbiter, plan.edits, (expected as string[] | undefined) ?? [], {
    reason: `Changed on the Rules page (${action})`,
    requestedBy: "rules-page",
    approver: RULES_PAGE_APPROVER,
    moved: MOVED,
    basedOn,
    stale: STALE,
  });
  json(res, r.status, r.body);
}

/**
 * GET /api/policy/rules/source?id=<row id> (dashboard.md §4.25g): the lines
 * of policy.yaml the row stands for, as written on disk, for the page's
 * "Show in policy.yaml". Read-only.
 *   → { found: true, path, start, lines, mark, note? }
 *   → { found: false, path, reason }
 */
export async function getRuleSource(arbiter: PolicyDocArbiter, url: string, res: ServerResponse): Promise<void> {
  const id = new URLSearchParams(url.split("?")[1] ?? "").get("id") ?? "";
  if (id === "") return json(res, 400, { error: "which rule?" });
  let view;
  try {
    view = await arbiter.policyDocument();
  } catch (err) {
    return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
  }
  const path = view.status.path;
  const text = view.onDisk.text;
  if (text === null) return json(res, 200, { found: false, path, reason: "There is no policy.yaml yet. This rule comes from Mandu's built-in settings." });
  const found = locateRule(text, id);
  // A file the arbiter refused is not the law in force: say so beside its lines.
  const note = view.status.valid ? undefined : "This file has problems, so Mandu is still using the last version that worked.";
  json(res, 200, { path, ...found, ...(note && found.found ? { note } : {}) });
}
