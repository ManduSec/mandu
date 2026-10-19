/**
 * server/policy-doc-routes — the policy DOCUMENT routes (policy-surface-
 * redesign.md §2.1, stage 5a): read the law on disk / in force, replace it,
 * mint a user rule from Approvals, export DB-only secret-file labels into it.
 *
 *   GET  /api/policy/document        → { status, inForce, lawHash, onDisk }
 *   POST /api/policy/document        { document, lawHash, requestedBy? } → { path, status }
 *   POST /api/policy/rules           { rule, requestedBy? }     → { id, path, status }
 *   POST /api/policy/export-labels   { requestedBy? }           → { added, path, status }
 *
 * Every POST is a human decision: gated like every other mutating route (CSRF +
 * admin session) and enacted over the arbiter's ADMIN channel — an adopted
 * arbiter answers 503 with the remedy (isAdminBoundaryError). An INVALID
 * document is the arbiter's refusal (every problem listed) → 422, never a 200
 * for a law that was not written. A write the arbiter refuses because the file
 * changed on disk, or because a hand edit waiting in Approvals changes the same
 * rule (policy-surface.md §8.4.6), → 409 with its text. The whole document
 * names the law it was built from (`lawHash`, from the GET; required): one
 * built from a law that moved since is refused as stale → 409 with
 * `stale: true`, so the page reloads instead of undoing that change (`held:
 * true` on the held-edit refusal). The narrow arbiter surface follows the
 * arbiter-client pattern (server-main wires the real client; tests inject a
 * fake).
 */
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import type { PolicyAssistantArbiter } from "./policy-assistant-routes.js";
import type { SuggestionsArbiter } from "./suggestion-routes.js";
import type { PromptFiltersArbiter } from "./prompt-filter-routes.js";
import type { WhySymbolArbiter } from "./arbiter-surfaces.js";

export interface PolicyFileStatusRow {
  path: string | null;
  found: boolean;
  valid: boolean;
  problems: string[];
  loadedAt: number | null;
  refusedAt: number | null;
}

export interface PolicyDocumentView {
  status: PolicyFileStatusRow;
  inForce: unknown;
  /** The version of `inForce` (policy-surface.md §8.4.6): a whole document
   *  built from it is POSTed with it. Absent from an older arbiter. */
  lawHash?: string;
  /** The version of each item of `inForce`, `section → key → version`
   *  (policy-surface.md §8.4.6 "An item-level version"): a typed edit that
   *  carries fields over from this read names the items it read
   *  (`policyPropose.basedOn`). Absent from an older arbiter. */
  itemVersions?: Record<string, Record<string, string>>;
  /** The version of an item `inForce` does not have: a typed edit that
   *  creates an item where this read found none names it with this
   *  (policy-surface.md §8.4.6). Absent from an older arbiter. */
  absentVersion?: string;
  /** `warnings` (Plan 13 D8): advice on a valid document (a reader that runs
   *  any code); absent from an older arbiter. */
  onDisk: { text: string | null; parsed: unknown; problems: string[]; warnings?: string[] };
  /** Plan 12 D5: the administrator's layer, when one is in force (its
   *  `models:` as written, each with its `file`). */
  admin?: { files: string[]; locked: boolean; models: Array<Record<string, unknown>>; perimeter?: unknown; perimeterFile?: string | null; sensitivityLabels?: Array<Record<string, unknown>> };
}

export interface MintRuleInput {
  kind: "release";
  from?: { host?: string };
  to: { host: string };
  mode: "allow" | "block" | "audit" | "off";
  reason?: string;
  by?: string;
  expires?: string | null;
}

/** Test-a-flow input (policy-surface.md §4; arbiter op `testFlow`). */
export interface TestFlowInput {
  source?: { tool?: string; field?: string; origin?: string; params?: Record<string, string> };
  destination?: string;
  boundary?: "network" | "filesystem" | "shell" | "model_context";
  asCommand?: boolean;
  level?: string;
  /** Probe the law WITH these edits applied (the Describe box's "Try it"; nothing written). */
  withEdits?: unknown;
}

/** The NARROW arbiter surface these routes depend on. It also carries the
 *  policy agent surface's optional ops (policy-proposal-routes.ts). */
export interface PolicyDocArbiter extends PolicyAssistantArbiter, SuggestionsArbiter, PromptFiltersArbiter, WhySymbolArbiter {
  policyDocument(): Promise<PolicyDocumentView>;
  /** `lawHash`: the version of the law the document was built from (the
   *  GET's); the arbiter refuses the apply as stale when the law moved. */
  applyPolicyDocument(document: unknown, requestedBy: string | undefined, lawHash: string): Promise<{ path: string; status: PolicyFileStatusRow }>;
  mintUserRule(rule: MintRuleInput, requestedBy?: string): Promise<{ id: string; path: string; status: PolicyFileStatusRow }>;
  exportDbLabels(requestedBy?: string): Promise<{ added: number; path: string; status: PolicyFileStatusRow }>;
  /** Move the page's older rules (mandu.db) into policy.yaml, unchanged
   *  (dashboard.md §4.25m). ADMIN channel. Optional: an older arbiter → 501. */
  movePageLabels?(requestedBy?: string): Promise<{ moved: number; changeId: string | null }>;
  /** Test a flow (§4 / §5 "Tester ≡ gates"): a READ over the data socket.
   *  Optional — an arbiter predating the op answers 501, never a guess. */
  testFlow?(req: TestFlowInput): Promise<unknown>;
}

const BOUNDARIES = new Set(["network", "filesystem", "shell", "model_context"]);

/** POST /api/policy/test-flow {source?, destination?, boundary?, asCommand?, level?}
 *  → the arbiter's TestFlowResult verbatim. Shapes are checked, never coerced. */
export async function postTestFlow(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.testFlow) {
    json(res, 501, { error: "this arbiter has no Test-a-flow op — restart the Mandu stack on the current build" });
    return;
  }
  const raw = await readJson(req);
  if (raw === null || raw === undefined || typeof raw !== "object") {
    json(res, 400, { error: "invalid JSON body" });
    return;
  }
  const b = raw as Record<string, unknown>;
  const input: TestFlowInput = {};
  if (b["source"] !== undefined) {
    if (b["source"] === null || typeof b["source"] !== "object") return json(res, 400, { error: "source must be { tool?, field?, origin? }" });
    const s = b["source"] as Record<string, unknown>;
    const src: NonNullable<TestFlowInput["source"]> = {};
    for (const k of ["tool", "field", "origin"] as const) {
      if (s[k] === undefined) continue;
      if (typeof s[k] !== "string") return json(res, 400, { error: `source.${k} must be a string` });
      src[k] = s[k] as string;
    }
    if (s["params"] !== undefined) {
      const p = s["params"];
      if (p === null || typeof p !== "object" || Array.isArray(p) || Object.values(p as object).some((v) => typeof v !== "string")) {
        return json(res, 400, { error: "source.params must be a mapping of strings" });
      }
      src.params = p as Record<string, string>;
    }
    input.source = src;
  }
  if (b["destination"] !== undefined) {
    if (typeof b["destination"] !== "string") return json(res, 400, { error: "destination must be a string" });
    input.destination = b["destination"];
  }
  if (b["boundary"] !== undefined) {
    if (typeof b["boundary"] !== "string" || !BOUNDARIES.has(b["boundary"])) return json(res, 400, { error: "boundary must be network | filesystem | shell | model_context" });
    input.boundary = b["boundary"] as TestFlowInput["boundary"];
  }
  if (b["asCommand"] !== undefined) {
    if (typeof b["asCommand"] !== "boolean") return json(res, 400, { error: "asCommand must be a boolean" });
    input.asCommand = b["asCommand"];
  }
  if (b["level"] !== undefined) {
    if (typeof b["level"] !== "string") return json(res, 400, { error: "level must be a string" });
    input.level = b["level"];
  }
  try {
    json(res, 200, await arbiter.testFlow(input));
  } catch (err) {
    json(res, statusFor(err), { error: (err as Error).message });
  }
}

function statusFor(err: unknown): number {
  if (isAdminBoundaryError(err)) return 503;
  const msg = String((err as Error)?.message ?? err);
  if (/is invalid|refuses to start|refuses/.test(msg)) return 422;
  if (/in-memory document/.test(msg)) return 409;
  // The file changed on disk since it was read, or a hand edit waiting in
  // Approvals changes the same rule (policy-surface.md §8.4.6): nothing was
  // written; the person reloads, or answers that change first.
  // A whole document built from a law that moved since it was read (§8.4.6):
  // nothing was written; the person reloads and makes the change again.
  if (/changed on disk|waits for a human in Approvals|changed since this document was read/.test(msg)) return 409;
  return 502;
}

/** The arbiter's refusals the page answers by reading the law again
 *  (`stale`: the file or the law moved since it was read) or by deciding
 *  the held change first (`held`), StalePolicyError's texts. */
function refusalFlags(err: unknown): { stale?: true; held?: true } {
  const msg = String((err as Error)?.message ?? err);
  if (/waits for a human in Approvals/.test(msg)) return { held: true };
  if (/changed on disk|changed since this document was read/.test(msg)) return { stale: true };
  return {};
}

export async function getPolicyDocument(arbiter: PolicyDocArbiter, res: ServerResponse): Promise<void> {
  try {
    json(res, 200, await arbiter.policyDocument());
  } catch (err) {
    json(res, 503, { error: String((err as Error)?.message ?? err) });
  }
}

export async function postPolicyDocument(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readJson(req);
  // `lawHash`: the GET's, of the law the document was built from. Required:
  // a document that names no law could undo a change it never saw.
  const lawHashIn = (body as { lawHash?: unknown } | null | undefined)?.lawHash;
  if (body === undefined || typeof body !== "object" || body === null || !("document" in body) || typeof lawHashIn !== "string" || lawHashIn === "") {
    json(res, 400, { error: "body must be { document, lawHash, requestedBy? }: lawHash is the one GET /api/policy/document gave with the law the document was built from" });
    return;
  }
  const { document, requestedBy, lawHash } = body as { document: unknown; requestedBy?: unknown; lawHash: string };
  try {
    json(res, 200, await arbiter.applyPolicyDocument(document, typeof requestedBy === "string" ? requestedBy : "dashboard", lawHash));
  } catch (err) {
    json(res, statusFor(err), { error: `arbiter: ${String((err as Error)?.message ?? err)}`, ...refusalFlags(err) });
  }
}

const MODES = new Set(["allow", "block", "audit", "off"]);

export async function postMintRule(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readJson(req);
  const rule = (body as { rule?: unknown } | undefined)?.rule as Partial<MintRuleInput> | undefined;
  if (!rule || typeof rule !== "object" || rule.kind !== "release" || !rule.to || typeof rule.to.host !== "string" || rule.to.host.trim() === "" || !MODES.has(rule.mode as string)) {
    json(res, 400, { error: "body must be { rule: { kind: 'release', from?: { host }, to: { host }, mode: allow|block|audit|off, reason?, expires? }, requestedBy? }" });
    return;
  }
  const requestedBy = (body as { requestedBy?: unknown }).requestedBy;
  try {
    json(res, 200, await arbiter.mintUserRule(rule as MintRuleInput, typeof requestedBy === "string" ? requestedBy : "dashboard"));
  } catch (err) {
    json(res, statusFor(err), { error: `arbiter: ${String((err as Error)?.message ?? err)}` });
  }
}

export async function postExportLabels(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson(req)) as { requestedBy?: unknown } | undefined;
  try {
    json(res, 200, await arbiter.exportDbLabels(typeof body?.requestedBy === "string" ? body.requestedBy : "dashboard"));
  } catch (err) {
    json(res, statusFor(err), { error: `arbiter: ${String((err as Error)?.message ?? err)}` });
  }
}
