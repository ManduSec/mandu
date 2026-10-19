/**
 * server/sensitivity-label-routes — Settings › Sensitivity labels
 * (confidentiality-plan-14-policy-suggestions.md §14.1; dashboard.md §4.25s):
 *
 *   GET  /api/policy/sensitivity-labels  → { labels: LabelSettingsVM }
 *        The mappings in force (the person's `sensitivity_labels:` entries,
 *        then the administrator's, read-only with their file, from the
 *        `policyDocument` op) and the labels the last scan this dashboard
 *        ran found that no mapping names (suggestion-routes.ts
 *        `lastLabelScan`: label ids and file counts only).
 *   POST /api/policy/sensitivity-labels/change
 *        { action: "map", id, site?, name, level, version, expected? }
 *        { action: "unmap", id, site?, version, expected? }
 *        `version`: the row's version as the page read it (required)
 *        → { applied: false, confirm: true, expected, rows, wouldLet }
 *          (the change lowers what Mandu suggests: a removed mapping, a
 *          lower level, a new "Not secret" one, a new name; ask the person,
 *          then send the same body with `expected`)
 *        → { applied: true, changeId, note }
 *        → 409 { stale: true, changed, error } the mapping changed since it
 *          was read: nothing saved
 *
 * A row's Save rewrites the mapping whole (`map-sensitivity-label` replaces
 * the entry), carrying the name the row was filled from; a Save on a label
 * with no level yet makes the mapping. So each change names the mapping
 * with the version the page read (`basedOn`, policy-surface.md §8.4.6 "An
 * item-level version"; the absent version for a mapping not made yet), and
 * the arbiter refuses it, nothing written, once that mapping changed: a
 * level set meanwhile somewhere else (another tab, a hand edit) is never
 * put back to what the row was filled from. Another mapping's change does
 * not refuse it. An arbiter that answers no versions is sent no change (501).
 *
 * The edit is planned here into the one edit grammar (map-sensitivity-label
 * / unmap-sensitivity-label, arbiter/policy/policy-edit.ts) and applied by
 * the human-apply sequence Settings › Models uses (`applyAsHuman`: preview,
 * refuse a loosening that was not shown, propose on the ADMIN channel,
 * approve at once). Recorded, and undoable from History.
 *
 * GATES. The GET names nothing but label ids, names and counts, but it is
 * served like the Suggested view's listing (CSRF header AND the admin
 * session, server.ts), since it reports what the last scan found. The POST
 * sits behind the global mutating gate (CSRF + admin session).
 */
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import { applyAsHuman } from "./policy-assistant-routes.js";
import type { PolicyDocArbiter } from "./policy-doc-routes.js";
import { lastLabelScan } from "./suggestion-routes.js";
import { SETTINGS_APPROVER } from "./model-routes.js";
import { relaxKey } from "../policy-assistant.js";
import { editRow, relaxLine } from "../view-model/policy-proposals.js";
import { labelItemKey, labelSettingsVM, labelStaleWords, labelVersionOf, normalizeGuid, planLabelChange } from "../view-model/sensitivity-labels.js";

const UNSUPPORTED = "this Mandu service cannot change sensitivity labels from this page; restart the Mandu stack on the current build";
const MOVED = "Your sensitivity labels changed while you were deciding. Nothing was changed. Try again.";
const GONE = "This label has no level any more. Reload the page.";
const UNREAD = "This page did not say which version of the label it showed you. Reload the page and choose again.";
const VERSION_RE = /^[0-9a-f]{32}$/;
/** Said after every applied change. */
export const LABEL_NOTE = "Mandu's next scan suggests with this. What is protected now does not change until you save a suggestion.";

export async function getSensitivityLabels(arbiter: PolicyDocArbiter, res: ServerResponse): Promise<void> {
  try {
    const pd = await arbiter.policyDocument();
    json(res, 200, { labels: labelSettingsVM(pd.inForce, pd.admin, lastLabelScan(arbiter), pd) });
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `the protection service did not answer (${String((err as Error)?.message ?? err)})` });
  }
}

/** The validator's lines without the file position. */
function formProblems(problems: readonly string[]): string[] {
  return problems.map((p) => p.replace(/^sensitivity_labels\[\d+\]\./, "").replace(/^edits\[\d+\] \([a-z-]+\): /, ""));
}

export async function postSensitivityLabelChange(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.policyPreview || !arbiter.policyPropose || !arbiter.resolvePolicyProposal) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as Record<string, unknown> | undefined;
  const expected = body?.["expected"];
  if (expected !== undefined && (!Array.isArray(expected) || !expected.every((k) => typeof k === "string"))) {
    return json(res, 400, { error: "expected must be the list this route answered with" });
  }
  const plan = planLabelChange(body);
  if (!plan.ok) return json(res, plan.status, { error: plan.error });
  // The version of the mapping the row was filled from (§8.4.6 "An
  // item-level version"): a change is refused without it.
  const version = body?.["version"];
  if (typeof version !== "string" || !VERSION_RE.test(version)) return json(res, 400, { error: UNREAD });
  let now: string | null;
  let name: string;
  try {
    const pd = await arbiter.policyDocument();
    now = labelVersionOf(pd, plan.key);
    const own = (pd.inForce as { sensitivity_labels?: Array<{ id?: unknown; site?: unknown; name?: unknown }> } | null)?.sensitivity_labels ?? [];
    const keyOf = (l: { id?: unknown; site?: unknown }): string | null => {
      const id = normalizeGuid(l.id);
      return id === null ? null : labelItemKey(id, l.site === undefined || l.site === null ? null : normalizeGuid(l.site));
    };
    const read = own.find((l) => keyOf(l) === plan.key);
    name = plan.name ?? (typeof read?.name === "string" && read.name !== "" ? read.name : String(body?.["id"]));
  } catch (err) {
    return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
  }
  // An arbiter that answers no versions could not refuse a stale change.
  if (now === null) return json(res, 501, { error: UNSUPPORTED });
  const action = body?.["action"] === "unmap" ? "unmap" : "map";
  const changed = [`sensitivity-labels ${plan.key}`];
  // Changed before the question: said now, not after the person confirms.
  if (now !== version) return json(res, 409, { error: labelStaleWords(name, action), stale: true, changed });
  const basedOn = [{ section: "sensitivity-labels", key: plan.key, version }];

  if (expected === undefined) {
    let preview;
    try {
      preview = await arbiter.policyPreview(plan.edits);
    } catch (err) {
      return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
    }
    if (!preview.ok) {
      if (preview.problems.some((p) => /\bno mapping for the label\b/.test(p))) return json(res, 409, { error: GONE });
      if (preview.problems.some((p) => /unknown op/.test(p))) return json(res, 501, { error: UNSUPPORTED });
      return json(res, 422, { error: "This label setting is not valid.", problems: formProblems(preview.problems) });
    }
    if (preview.relaxations.length > 0) {
      return json(res, 200, {
        applied: false,
        confirm: true,
        expected: preview.relaxations.map(relaxKey),
        rows: plan.edits.map(editRow),
        wouldLet: preview.relaxations.map(relaxLine),
        warnings: [],
      });
    }
  }
  const r = await applyAsHuman(arbiter, plan.edits, (expected as string[] | undefined) ?? [], {
    reason: `Changed in Settings › Sensitivity labels (${String(body?.["action"])})`,
    requestedBy: "settings",
    approver: SETTINGS_APPROVER,
    moved: MOVED,
    basedOn,
    stale: labelStaleWords(name, action),
  });
  if (r.status === 422 && Array.isArray(r.body["problems"])) r.body["problems"] = formProblems(r.body["problems"] as string[]);
  json(res, r.status, r.status === 200 ? { ...r.body, note: LABEL_NOTE } : r.body);
}
