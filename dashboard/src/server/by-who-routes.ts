/**
 * by-who-routes — `GET /api/policy/by-who`, the Rules page's per-principal
 * view (confidentiality plan 13 §5.3, dashboard.md §4.25aa). Mandu-new.
 *
 * Read only. The server projects (view-model/rules-by-who.ts, unit-tested),
 * the page paints (public/js/home.js `renderByWho`). It reads the two places
 * file rules live: policy.yaml's `paths:` (the policy snapshot's document,
 * with each reader entry's judgment) and the labels made on the page (the
 * confidentiality state's labels whose source is not the policy file).
 *
 * Fail soft, never a 500: no snapshot (no protection service, an older one)
 * answers `available: false`, which the page words as "could not be read",
 * never as "nothing". A confidentiality state that fails while the snapshot
 * answers gives the policy.yaml rules with `partial: true`.
 *
 * Carries paths, program names, hosts and model names, never a value; sent
 * uncompressed (json, never jsonConditional) like the panel it mirrors.
 */

import type { ServerResponse } from "node:http";

import { json } from "./http-util.js";
import type { EventSource } from "../event-source.js";
import type { PolicySnapshot } from "../policy-model.js";
import type { SecretsArbiter } from "./secrets-routes.js";
import { byWhoRules, toByWhoVM, type ByWhoVM } from "../view-model/rules-by-who.js";
import { filePaths } from "./path-kinds.js";

export async function loadByWho(source: EventSource, secrets: SecretsArbiter | undefined, home = ""): Promise<ByWhoVM> {
  let snapshot: PolicySnapshot | null = null;
  try {
    snapshot = ((await source.policySnapshot?.()) ?? null) as PolicySnapshot | null;
  } catch {
    snapshot = null;
  }
  const doc = snapshot?.document;
  if (!doc) return toByWhoVM(null, null, { home });
  let labels: unknown[] | null = null;
  if (secrets) {
    try {
      const state = await secrets.confidentialityState();
      labels = Array.isArray(state.labels) ? state.labels : [];
    } catch {
      labels = null;
    }
  }
  // A rule reaching everything inside a file is listed as that file
  // (path-kinds.ts; display only).
  const recursive = [
    ...(doc.paths ?? []).filter((p) => p.recursive).map((p) => p.path),
    ...(labels ?? []).flatMap((l) => {
      const { path, recursive: r } = (l ?? {}) as { path?: unknown; recursive?: unknown };
      return typeof path === "string" && r !== false ? [path] : [];
    }),
  ];
  const files = await filePaths(recursive);
  return toByWhoVM(byWhoRules(doc.paths, labels as Parameters<typeof byWhoRules>[1], files), doc.models, {
    home,
    partial: labels === null,
  });
}

/** GET /api/policy/by-who → { byWho }. */
export async function apiPolicyByWho(source: EventSource, secrets: SecretsArbiter | undefined, res: ServerResponse, home = ""): Promise<void> {
  json(res, 200, { byWho: await loadByWho(source, secrets, home) });
}
