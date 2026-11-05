/**
 * host-check-routes — `GET /api/policy/host-check?host=…`, the Rules page's
 * "Check a host" box (dashboard.md §4.25aa *Check a host*). Mandu-new.
 *
 * Read only: it asks the arbiter's `whyHost` (`mandu why <host>`), which
 * reads the rules and probes the egress gate with nothing queued and
 * nothing counted, and answers `{ check }` in the page's words
 * (view-model/host-check.ts, unit-tested). Carries paths, names, hosts and
 * decisions, never a value: the answer's earlier-answer placeholders are
 * counted in the view-model and never sent. Uncompressed (json), like the
 * by-who view beside it.
 *
 * 400: a host the box refuses (in words). 501: an arbiter without
 * `whyHost`, so the page hides the box. 503 / 502: the protection service
 * did not answer, as `GET /api/files/why` says it.
 */

import { homedir } from "node:os";
import type { ServerResponse } from "node:http";

import { isAdminBoundaryError, json } from "./http-util.js";
import type { SecretsArbiter } from "./secrets-routes.js";
import { checkedHost, hostCheckWords, type WhyHostWire } from "../view-model/host-check.js";

const UNSUPPORTED = "this Mandu service cannot check a host; restart the Mandu stack on the current build";

/** GET /api/policy/host-check?host=… → { check }. */
export async function getHostCheck(secrets: SecretsArbiter | undefined, url: string, res: ServerResponse, home = homedir()): Promise<void> {
  if (!secrets?.whyHost) return json(res, 501, { error: UNSUPPORTED });
  const params = new URLSearchParams(url.split("?")[1] ?? "");
  const asked = checkedHost(params.get("host"));
  if ("error" in asked) return json(res, 400, { error: asked.error });
  try {
    const answer = (await secrets.whyHost(asked.host)) as WhyHostWire;
    json(res, 200, { check: hostCheckWords(answer, home) });
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `the protection service did not answer (${(err as Error).message})` });
  }
}
