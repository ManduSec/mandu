/**
 * server/secrets-routes — the confidentiality surface: the standing-release view
 * (`GET /api/secrets`) and THE LABELING ACT (`POST|DELETE /api/secrets/label`).
 *
 * WHAT THIS RENDERS AND WHY (confidentiality.md §6): every registered secret and
 * every destination BINDING is a **standing release rule** — a datum that may
 * leave to that host with no further human decision. §6 therefore REQUIRES the
 * whole surface be visible; an invisible standing rule is how DLP deployments
 * rot. This route is that visibility.
 *
 * WHAT IT MUST NEVER RENDER: the secret's CONTENTS. The panel answers "what is
 * confined, at what level, and where may it go" — not "what is inside". The
 * arbiter's `confidentialityState` op is shaped to make that structural (it
 * returns no values at all), and the view-model copies fields explicitly.
 *
 * WHAT IT MUTATES (plan 6): the user LABEL store. This is the only producer of
 * `any-model` and `local-model` in the system — the default catalog yields public/strict
 * only, deliberately, because the level encodes a clearance decision (ZDR/BAA/
 * local model) that no code can observe. So the label routes are a security
 * surface, not a preferences pane:
 *
 *   - they are CSRF-gated in server.ts (`requireCsrf`), exactly like the egress
 *     approval verdicts — a labeling act is a human decision, and a page on the
 *     other side of the browser must not be able to forge one;
 *   - an unknown level is REJECTED with 400, never coerced. Coercing up would
 *     silently lock a user out of their own file; coercing down would silently
 *     release a credential. A labeling act is explicit or it is not an act;
 *   - an arbiter that cannot answer is a 502 — never a green "no secrets
 *     confined" and never a silently-accepted label.
 */

import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import {
  CONFIDENTIALITY_LEVELS,
  isConfidentialityLevel,
  toSecretsPanel,
  type ConfidentialityLevelName,
  type DerivedLabelWire,
  type PathLabelWire,
  type SecretsPanel,
} from "../view-model/secrets.js";
import type { PathLevelsEntryWire } from "../view-model/file-browser.js";
import { filePaths } from "./path-kinds.js";

export type { DerivedLabelWire, PathLabelWire } from "../view-model/secrets.js";

/** One registered secret. Mirrors the arbiter's `confidentialityState` wire
 *  result (declared here, not imported — the dashboard typechecks standalone;
 *  same decoupling rationale as approval-routes.ts). NO value field, by design. */
export interface RegisteredSecret {
  /** Absolute path of the confined file. */
  path: string;
  /** The symbol standing for its contents. */
  symbol: string;
  /** "no-model" | "local-model" | "any-model". */
  level: string;
  /** Bound destinations — the standing release rules. Empty = none. */
  bindings: string[];
  /** Plan 10: values with their own symbol (0 = whole-file twin). */
  fields?: number;
  /** Plan 10: programs that may open the raw file; absent = twin for all. */
  readers?: string[];
  /** Plan 13 D8: per `readers` entry, the arbiter's word on whether it admits nothing. */
  readersAdmitNothing?: boolean[];
  /** Plan 13 D8 (12): per `readers` entry, its program reads the placeholder copy. */
  readersReadTwin?: boolean[];
}

export interface ConfidentialityState {
  /** Is the axis enabled on this arbiter (confidentiality.md §11 kill switch)? */
  enabled: boolean;
  secrets: RegisteredSecret[];
  /** USER LABELS (plan 6) — part of the SAME standing-release surface: a
   *  `any-model` label is a standing grant of model readability, and a
   *  `public` label on a catalog-matching path is a standing DECLASSIFICATION.
   *  Optional so an arbiter build predating plan 6 still renders (as no labels)
   *  rather than crashing the panel. */
  labels?: PathLabelWire[];
  /** DERIVED LABELS (plan 9) — the files a HIGH session wrote, labeled on disk at
   *  its watermark (§4/§8). Optional so an arbiter predating plan 9 still renders.
   *  A SEPARATE list from `labels`: those are human decisions, these are machine
   *  taint records, and the UI must never present one as the other. */
  derived?: DerivedLabelWire[];
  /** Plan 10 §11.9: programs that read a secret raw. Optional (older arbiters). */
  taintedProcesses?: Array<{ procKey: string; app: string; path: string; level: string; session?: string | null; since: number }>;
}

/** The result of one labeling act (arbiter `setPathLabel`). */
export interface PathLabelResult {
  path: string;
  level: string;
  bindings: string[];
  recursive: boolean;
  /** True ⇒ WEAKER than the catalog's verdict: a standing declassification. */
  declassifies: boolean;
}

/** The NARROW arbiter surface this route depends on (the arbiter-client pattern —
 *  see anthropic-proxy/src/arbiter-client.ts). server-main wires the real arbiter
 *  IPC client behind this; the tests inject an in-memory fake. */
export interface SecretsArbiter {
  confidentialityState(): Promise<ConfidentialityState>;
  /** THE LABELING ACT. Rejects (throws) an invalid level or a relative path. */
  setPathLabel(args: {
    path: string;
    confidentiality: string;
    bindings?: string[];
    recursive?: boolean;
  }): Promise<PathLabelResult>;
  /** Remove a label; false when no such label existed. */
  removePathLabel(path: string): Promise<boolean>;
  /** Clear a DERIVED taint record (§8's declassification, the blunt form — the
   *  standing form is a user label on the same path). Optional: an arbiter
   *  predating plan 9 has no derived store, and the UI simply shows no rows. */
  removeDerivedLabel?(path: string): Promise<boolean>;
  /** The file browser's labels (dashboard.md §4.25m): `pathLevel` for many
   *  paths, plus where each deciding rule is kept. A READ on the data socket.
   *  Optional: an arbiter predating the op → the browser lists files with
   *  their labels shown as unknown. */
  pathLevels?(paths: string[], home?: string, withEdits?: unknown): Promise<{ axis: boolean; levels: PathLevelsEntryWire[] }>;
  /** `mandu why <path>`: the rules' view of one file (a data-socket READ).
   *  Optional: an older arbiter → the browser's Why answers 501. */
  whyPath?(path: string, home?: string): Promise<unknown>;
}

/** The GET body: the axis switch and the projected panel (the pure
 *  view-model): the projection lives in TS and is unit-tested; the browser
 *  shell only paints it. The arbiter's raw state is NOT shipped beside it
 *  (until 2026-10-03 it was, so every secret, label, derived record and
 *  tainted program went out twice; no client read the raw copy, dashboard.md
 *  §4.30). The panel copies each field it shows by name, so a field the
 *  arbiter adds to its state does not reach the browser by accident.
 *  Uncompressed on purpose (json, never jsonConditional): the inventory sits
 *  beside agent-chosen paths, the mix a compression side channel works on. */
export interface SecretsResponse {
  enabled: boolean;
  panel: SecretsPanel;
}

/** GET /api/secrets → { enabled, panel }. */
export async function getSecrets(
  arbiter: SecretsArbiter,
  res: ServerResponse,
): Promise<void> {
  try {
    const state = await arbiter.confidentialityState();
    // A label reaching everything inside a file reads as that file on the
    // product page (path-kinds.ts; display only).
    const recursive = (Array.isArray(state.labels) ? state.labels : [])
      .flatMap((l) => (typeof l?.path === "string" && l.recursive !== false && l.glob !== true ? [l.path] : []));
    const panel = toSecretsPanel(state, await filePaths(recursive));
    const body: SecretsResponse = { enabled: panel.enabled, panel };
    json(res, 200, body);
  } catch (err) {
    // An arbiter that cannot answer must not render as "no secrets confined" —
    // that reads as a green light for a state we cannot vouch for.
    json(res, 502, { error: `arbiter: ${(err as Error).message}` });
  }
}

// ── the labeling act ──────────────────────────────────────────────────────────

interface LabelRequestBody {
  path: string;
  confidentiality: ConfidentialityLevelName;
  bindings: string[];
  recursive: boolean;
}

/** Parse + VALIDATE a label request body. Returns an error string (→ 400) rather
 *  than throwing, and never coerces: an unparseable field is a rejected act. */
function parseLabelBody(raw: unknown): LabelRequestBody | string {
  if (raw === undefined || raw === null || typeof raw !== "object") {
    return "invalid JSON body";
  }
  const b = raw as Record<string, unknown>;

  const path = parsePath(b["path"]);
  if ("error" in path) return path.error;

  const level = b["confidentiality"];
  if (!isConfidentialityLevel(level)) {
    // FAIL-CLOSED-BY-REJECTION: we do NOT coerce to no-model here. Coercion
    // would let a typo ("public " / "modelok") become a level the human did not
    // choose — in one direction a silent lockout, in the other a silent release.
    return (
      `invalid confidentiality level ${JSON.stringify(level)} — ` +
      `must be one of ${CONFIDENTIALITY_LEVELS.join(" | ")} (a level is never coerced)`
    );
  }

  const bindingsRaw = b["bindings"];
  let bindings: string[] = [];
  if (bindingsRaw !== undefined && bindingsRaw !== null) {
    if (!Array.isArray(bindingsRaw) || bindingsRaw.some((x) => typeof x !== "string")) {
      return "bindings must be an array of destination strings";
    }
    bindings = (bindingsRaw as string[]).map((s) => s.trim()).filter((s) => s !== "");
  }

  const recursiveRaw = b["recursive"];
  if (recursiveRaw !== undefined && typeof recursiveRaw !== "boolean") {
    return "recursive must be a boolean";
  }
  const recursive = recursiveRaw === undefined ? true : recursiveRaw;

  return { path: path.path, confidentiality: level, bindings, recursive };
}

/** A path must be present and ABSOLUTE (`/…` or `~/…`) — the arbiter rejects a
 *  relative one, and a relative label would silently apply to nothing. */
function parsePath(raw: unknown): { path: string } | { error: string } {
  if (typeof raw !== "string" || raw.trim() === "") return { error: "path is required" };
  const p = raw.trim();
  if (!p.startsWith("/") && !p.startsWith("~")) {
    return { error: `path must be absolute (got ${JSON.stringify(p)})` };
  }
  return { path: p };
}

/** POST /api/secrets/label {path, confidentiality, bindings?, recursive?} → { label }.
 *  CSRF-gated by server.ts. */
export async function setSecretLabel(
  arbiter: SecretsArbiter,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const parsed = parseLabelBody(await readJson(req));
  if (typeof parsed === "string") {
    json(res, 400, { error: parsed });
    return;
  }
  try {
    const label = await arbiter.setPathLabel({
      path: parsed.path,
      confidentiality: parsed.confidentiality,
      bindings: parsed.bindings,
      recursive: parsed.recursive,
    });
    json(res, 200, { label });
  } catch (err) {
    // The label was NOT stored. Say so with a 502 — never a 200 that lets the
    // human believe a standing rule now exists when it does not. 503 when the
    // cause is the admin boundary (policy-surface.md §2.6).
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `arbiter: ${(err as Error).message}` });
  }
}

/** DELETE /api/secrets/label {path} → { removed, path }. CSRF-gated by server.ts. */
export async function removeSecretLabel(
  arbiter: SecretsArbiter,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const raw = await readJson(req);
  if (raw === undefined || raw === null || typeof raw !== "object") {
    json(res, 400, { error: "invalid JSON body" });
    return;
  }
  const parsed = parsePath((raw as Record<string, unknown>)["path"]);
  if ("error" in parsed) {
    json(res, 400, { error: parsed.error });
    return;
  }
  try {
    const removed = await arbiter.removePathLabel(parsed.path);
    json(res, 200, { removed, path: parsed.path });
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `arbiter: ${(err as Error).message}` });
  }
}

/** DELETE /api/secrets/derived {path} → { removed, path }. CSRF-gated by server.ts.
 *
 *  §8's first-class declassification: forget that a high session wrote this file.
 *  Conservative tainting grows monotonically, and without a low-friction release
 *  "utility dies by over-taint" — so this act exists, and it is one click. It does
 *  NOT stop a FUTURE high session from re-tainting the path on the next write:
 *  that would be a standing release, which is what a user label is for. */
export async function removeDerivedLabel(
  arbiter: SecretsArbiter,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const raw = await readJson(req);
  if (raw === undefined || raw === null || typeof raw !== "object") {
    json(res, 400, { error: "invalid JSON body" });
    return;
  }
  const parsed = parsePath((raw as Record<string, unknown>)["path"]);
  if ("error" in parsed) {
    json(res, 400, { error: parsed.error });
    return;
  }
  if (!arbiter.removeDerivedLabel) {
    json(res, 501, { error: "this arbiter predates the derived on-disk label (plan 9)" });
    return;
  }
  try {
    const removed = await arbiter.removeDerivedLabel(parsed.path);
    json(res, 200, { removed, path: parsed.path });
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `arbiter: ${(err as Error).message}` });
  }
}
