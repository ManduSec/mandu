/**
 * server/suggestion-routes — the Files and folders explorer's Suggested view
 * (confidentiality-plan-14-policy-suggestions.md §5.4; dashboard.md §4.25r):
 *
 *   GET  /api/suggestions               → { suggestions: SuggestionRowVM[], count, scan }
 *   POST /api/suggestions/scan {root?, includeHome?}  → { scan, suggestions, count }
 *        Mandu's scans (`suggestPolicy`: the git history and the files as
 *        they are now, plan 14 §13) over `root` when the person typed one,
 *        else over the folders the recorded sessions worked in
 *        (home-routes.ts recentWorkspaces). `includeHome: true` ("Also look
 *        in your home folder") adds the home tier: only files named like
 *        configuration or keys, depth 4 (§13.1), with this page's HOME as
 *        `home`. It answers when the scans end or after SCAN_WAIT_MS,
 *        whichever is first; a scan still running goes on, and the GET says
 *        when it ends. It sets `countLabels` (plan 14 §14.1): an explicit
 *        scan reads the Office files' sensitivity labels even while no
 *        mapping is in force, so the person can map them; the label counts
 *        of the last finished scan are kept here (`lastLabelScan`) for
 *        Settings › Sensitivity labels.
 *   POST /api/suggestions/apply {ids}   → { applied, refused, suggestions, count }
 *        One click on Save: each ticked suggestion is approved on the ADMIN
 *        channel (`resolvePolicyProposal`, `via: "proposal"`), one change
 *        each in History, attributed to "dashboard" and proposed by
 *        mandu:scan. The arbiter applies a suggestion only as a pure
 *        tightening of the law in force, so no weaker-change question can
 *        arise here; anything else comes back in `refused` and stays pending.
 *   POST /api/suggestions/dismiss {id}  → "Not a secret" (`dismissSuggestion`,
 *        ADMIN only: it withholds protection); its finding is never filed again.
 *   POST /api/suggestions/model/preview {tier, endpoint?, root?, includeHome?}
 *        → { preview: ModelPreviewVM }   (plan 14 §14.5, §14.11; dashboard.md
 *        §4.25t) the model picker's run: `modelSuggestPreview` builds, gates
 *        and KEEPS what would be sent (Names only: every name as sent;
 *        Contents: only to a model of your own, the files and their sizes,
 *        never their text). Refused (403) unless this server runs with
 *        MANDU_EXPERIMENTAL_POLICY_MODEL=1.
 *   POST /api/suggestions/model/send {digest, tier} → { run: ModelRunVM, suggestions, count }
 *        Send: `modelSuggest` sends exactly the kept bytes, once; the answer
 *        comes when the run ends or after MODEL_WAIT_MS (`run.running`), and
 *        the page calls again with the same digest to follow it.
 *   GET /api/suggestions also answers `model` (ModelPickerVM): whether the
 *        picker is offered and which of your models Contents may use
 *        (`modelEndpoints`, only when offered).
 *
 * GATES. The GET is served only with the CSRF header AND the admin session
 * (server.ts), like the file browser's listing: it names paths where keys
 * were found, and a GET is open to any same-host process, the agent's
 * included. The POSTs sit behind the global mutating gate (CSRF + admin
 * session). The scan reads file contents only in the arbiter; what comes
 * back, and what this module serves, is paths, commit ids, the detector in
 * plain words and the scan's fixed masks: never a value.
 */
import { homedir } from "node:os";
import { posix } from "node:path";
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import type { PolicyProposalArbiter } from "./policy-proposal-routes.js";
import { tildePath } from "../view-model/file-browser.js";
import {
  modelErrorWords,
  modelPickerVM,
  modelPreviewVM,
  modelRunVM,
  type ModelEndpointFact,
  type ModelPickerVM,
  type ModelPreviewWire,
  type ModelRunWire,
} from "../view-model/suggestion-model.js";
import {
  BLOCKED_WORDS,
  type LabelScanWire,
  type ScanSummaryPart,
  scanSummaryParts,
  suggestionRows,
  type SuggestionRowVM,
  type SuggestionWire,
  type SuggestPolicyWire,
} from "../view-model/suggestions.js";

/** The narrow arbiter surface (arbiter-client pattern): all optional, so an
 *  arbiter predating plan 14 answers 501. `resolvePolicyProposal` is the
 *  proposal routes' own (admin channel). */
export interface SuggestionsArbiter extends Pick<PolicyProposalArbiter, "resolvePolicyProposal"> {
  suggestPolicy?(roots: string[], opts?: SuggestPolicyOpts): Promise<SuggestPolicyWire>;
  policySuggestions?(status?: SuggestionWire["status"]): Promise<{ suggestions: SuggestionWire[] }>;
  dismissSuggestion?(suggestionId: string, requestedBy?: string): Promise<{ suggestion: SuggestionWire }>;
  /** Plan 14 §14.5, §14.11: the model's two data-plane ops, and the declared
   *  models (a read). Optional: an arbiter predating them answers 501. */
  modelSuggestPreview?(roots: string[], opts: { tier: "names" | "contents"; endpoint?: string; home?: string; includeHome?: boolean }): Promise<ModelPreviewWire>;
  modelSuggest?(digest: string, opts?: { waitMs?: number }): Promise<ModelRunWire>;
  modelEndpoints?(): Promise<ModelEndpointFact[]>;
}

/** `suggestPolicy`'s options (arbiter/ipc/client.ts). */
export interface SuggestPolicyOpts {
  home?: string;
  waitMs?: number;
  sources?: Array<"git-history" | "workspace" | "sensitivity-label">;
  /** Also walk `home` as a home-tier root; needs an absolute `home`. */
  includeHome?: boolean;
  /** Plan 14 §14.1: read and count the Office files' sensitivity labels even
   *  while no mapping is in force (an explicit scan: this page's Scan). */
  countLabels?: boolean;
}

export interface SuggestionRouteDeps {
  arbiter: SuggestionsArbiter;
  /** What `~` means (the file browser's HOME). */
  home?: string;
  /** The folders the recorded sessions worked in, newest first. */
  workspaces: () => Promise<string[]>;
  /** How long the scan route waits before answering "still scanning". */
  waitMs?: number;
  /** Plan 14 §14.6: the model picker is offered only with
   *  MANDU_EXPERIMENTAL_POLICY_MODEL=1. Default: this process's environment. */
  modelOffered?: boolean;
  /** How long POST model/send waits before answering "still reading". */
  modelWaitMs?: number;
  /** The host the launches run on: it words each row's impact (a macOS
   *  launch hides no git history; view-model/suggestions.ts). Default: this
   *  process's. */
  platform?: NodeJS.Platform;
}

/** How long POST /api/suggestions/scan waits for the scan. */
export const SCAN_WAIT_MS = 20_000;
/** At most this many suggestions per Save. */
export const APPLY_MAX = 50;
export const SUGGESTION_ID = /^pp-\d{6}$/;
/** At most this many folders per scan: the arbiter's own cap
 *  (HISTORY_ROOTS_MAX); the newest sessions' folders come first. */
export const SCAN_ROOTS_MAX = 8;
/** How long POST /api/suggestions/model/send waits for the run. */
export const MODEL_WAIT_MS = 20_000;

/** Is the model picker offered (§14.6)? */
export function modelOffered(deps: Pick<SuggestionRouteDeps, "modelOffered">): boolean {
  return deps.modelOffered ?? (process.env["MANDU_EXPERIMENTAL_POLICY_MODEL"] ?? "") === "1";
}

/** The picker for GET /api/suggestions: the declared models are read only
 *  when it is offered; a failed read disables Contents with the reason. */
async function pickerFor(deps: SuggestionRouteDeps): Promise<ModelPickerVM> {
  const offered = modelOffered(deps);
  if (!offered) return modelPickerVM(false, []);
  if (!deps.arbiter.modelSuggestPreview || !deps.arbiter.modelEndpoints) return modelPickerVM(true, null);
  const endpoints = await deps.arbiter.modelEndpoints().catch(() => null);
  return modelPickerVM(true, endpoints);
}

const UNSUPPORTED = "this Mandu service cannot scan for keys yet; restart the Mandu stack on the current build";
export const NO_WORKSPACE = "No project is known yet: no agent has run under Mandu. Type the folder of a project to scan it.";
const BUSY = "Another scan is running (started from the terminal or when an agent started). Try again when it ends.";
export const NO_HOME = "Your home folder is not known to this page, so it cannot be scanned.";
const GONE = "It is no longer waiting: it was saved, marked as not a secret, or a rule of yours covers it now.";

/** The scan this dashboard started, per arbiter surface (a tenant). */
interface ScanState {
  running: boolean;
  startedAt: number | null;
  finishedAt: number | null;
  roots: string[];
  includeHome: boolean;
  summary: string | null;
  summaryParts: ScanSummaryPart[] | null;
  error: string | null;
  filed: number;
  /** Plan 14 §14.1: the label read of the last finished scan, and when. */
  labels: LabelScanWire | null;
  labelsAt: number | null;
}

export interface ScanStateVM {
  running: boolean;
  startedAt: number | null;
  finishedAt: number | null;
  /** The folders scanned, `~`-shortened. */
  roots: string[];
  /** The home folder was asked for too ("Also look in your home folder"). */
  includeHome: boolean;
  /** What it found, in one line (null while running or before any scan):
   *  `summaryParts` joined. */
  summary: string | null;
  /** The same line as parts, the place it names a link part (dashboard.md
   *  §4.25r); null with no summary. */
  summaryParts: ScanSummaryPart[] | null;
  error: string | null;
  /** Suggestions this scan filed. */
  filed: number;
}

const scans = new WeakMap<object, ScanState>();

function stateOf(arbiter: object): ScanState {
  let s = scans.get(arbiter);
  if (!s) {
    s = { running: false, startedAt: null, finishedAt: null, roots: [], includeHome: false, summary: null, summaryParts: null, error: null, filed: 0, labels: null, labelsAt: null };
    scans.set(arbiter, s);
  }
  return s;
}

function stateVM(s: ScanState): ScanStateVM {
  return { running: s.running, startedAt: s.startedAt, finishedAt: s.finishedAt, roots: [...s.roots], includeHome: s.includeHome, summary: s.summary,
    summaryParts: s.summaryParts === null ? null : s.summaryParts.map((p) => ({ ...p })), error: s.error, filed: s.filed };
}

/** Plan 14 §14.1: the sensitivity labels the last finished scan of this
 *  dashboard read (label ids and file counts; never a path or a file's
 *  words), for Settings › Sensitivity labels. Null before any scan that
 *  read them. */
export function lastLabelScan(arbiter: object): { labels: LabelScanWire; at: number } | null {
  const s = scans.get(arbiter);
  return s && s.labels && s.labelsAt !== null ? { labels: s.labels, at: s.labelsAt } : null;
}

function homeOf(deps: SuggestionRouteDeps): string {
  return deps.home ?? homedir();
}

/** The pending suggestions as rows. */
async function listing(deps: SuggestionRouteDeps): Promise<{ suggestions: SuggestionRowVM[]; count: number }> {
  const r = await deps.arbiter.policySuggestions!("pending");
  const rows = suggestionRows(r.suggestions, homeOf(deps), deps.platform ?? process.platform);
  return { suggestions: rows, count: rows.length };
}

function failStatus(err: unknown): number {
  if (isAdminBoundaryError(err)) return 503;
  return /unknown policy|already|not applied/.test(String((err as Error)?.message ?? err)) ? 409 : 502;
}

export async function getSuggestions(deps: SuggestionRouteDeps, res: ServerResponse): Promise<void> {
  if (!deps.arbiter.policySuggestions) return json(res, 501, { error: UNSUPPORTED });
  try {
    json(res, 200, { ...(await listing(deps)), scan: stateVM(stateOf(deps.arbiter)), model: await pickerFor(deps) });
  } catch (err) {
    json(res, failStatus(err), { error: `the protection service did not answer (${(err as Error).message})` });
  }
}

/** A typed folder: absolute or `~`-anchored, normalized; null otherwise. */
function resolveRoot(raw: string, home: string): string | null {
  let p = raw.trim();
  if (p === "~") p = home;
  else if (p.startsWith("~/")) p = posix.join(home, p.slice(2));
  if (!p.startsWith("/")) return null;
  p = posix.normalize(p);
  return p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
}

export async function postScan(deps: SuggestionRouteDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { arbiter } = deps;
  if (!arbiter.suggestPolicy || !arbiter.policySuggestions) return json(res, 501, { error: UNSUPPORTED });
  const home = homeOf(deps);
  const body = (await readJson(req)) as { root?: unknown; includeHome?: unknown } | undefined;
  if (body === undefined || body === null || typeof body !== "object") return json(res, 400, { error: "invalid JSON body" });
  // "Also look in your home folder": a boolean, and only with a HOME the
  // arbiter can use (absolute). Checked before anything else happens.
  if (body.includeHome !== undefined && typeof body.includeHome !== "boolean") {
    return json(res, 400, { error: "includeHome must be true or false" });
  }
  const includeHome = body.includeHome === true;
  if (includeHome && !posix.isAbsolute(home)) return json(res, 400, { error: NO_HOME });
  const state = stateOf(arbiter);
  const answer = async (status = 200): Promise<void> => {
    try {
      json(res, status, { scan: stateVM(state), ...(await listing(deps)) });
    } catch (err) {
      json(res, failStatus(err), { scan: stateVM(state), error: `the protection service did not answer (${(err as Error).message})` });
    }
  };
  if (state.running) return answer();

  let roots: string[];
  if (body.root !== undefined && body.root !== null && body.root !== "") {
    if (typeof body.root !== "string") return json(res, 400, { error: "root must be a folder path" });
    const r = resolveRoot(body.root, home);
    if (r === null) return json(res, 400, { error: "Give the folder as a full path, starting with / or ~." });
    roots = [r];
  } else {
    roots = (await deps.workspaces().catch(() => [])).slice(0, SCAN_ROOTS_MAX);
    // With the home folder asked for, it alone is something to scan.
    if (roots.length === 0 && !includeHome) return json(res, 400, { error: NO_WORKSPACE, needsRoot: true });
  }

  Object.assign(state, { running: true, startedAt: Date.now(), finishedAt: null, roots: roots.map((r) => tildePath(r, home)), includeHome, summary: null, summaryParts: null, error: null, filed: 0 });
  // Every source (`sources` left out): the git history, the files and the
  // documents' sensitivity labels, counted even with no mapping (plan 14
  // §14.1: this is an explicit scan).
  const job = arbiter.suggestPolicy(roots, { home, countLabels: true, ...(includeHome ? { includeHome: true } : {}) }).then(
    (r) => {
      const labels = r.workspaceScan?.labels ?? null;
      const parts = scanSummaryParts(r, home);
      Object.assign(state, { running: false, finishedAt: Date.now(), summary: parts.map((p) => p.text).join(""), summaryParts: parts, filed: r.counts.filed });
      if (labels && labels.mode !== "off") Object.assign(state, { labels, labelsAt: Date.now() });
    },
    (err: unknown) => {
      const msg = String((err as Error)?.message ?? err);
      Object.assign(state, { running: false, finishedAt: Date.now(), error: /already running/.test(msg) ? BUSY : `The scan did not finish: ${msg}` });
    },
  );
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([job, new Promise<void>((r) => { timer = setTimeout(r, deps.waitMs ?? SCAN_WAIT_MS); timer.unref?.(); })]);
  if (timer) clearTimeout(timer);
  return answer();
}

function idList(raw: unknown): string[] | string {
  if (!Array.isArray(raw) || raw.length === 0) return "ids must be a non-empty list";
  if (raw.length > APPLY_MAX) return `at most ${APPLY_MAX} at once`;
  if (!raw.every((id) => typeof id === "string" && SUGGESTION_ID.test(id))) return "ids must be suggestion ids";
  if (new Set(raw).size !== raw.length) return "an id is listed twice";
  return raw as string[];
}

export async function postApply(deps: SuggestionRouteDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { arbiter } = deps;
  if (!arbiter.resolvePolicyProposal || !arbiter.policySuggestions) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { ids?: unknown } | undefined;
  const ids = idList(body?.ids);
  if (typeof ids === "string") return json(res, 400, { error: ids });
  let pending: Map<string, SuggestionWire>;
  try {
    pending = new Map((await arbiter.policySuggestions("pending")).suggestions.map((s) => [s.id, s]));
  } catch (err) {
    return json(res, failStatus(err), { error: `the protection service did not answer; nothing was saved (${(err as Error).message})` });
  }
  const applied: Array<{ id: string; changeId: string | null }> = [];
  const refused: Array<{ id: string; error: string }> = [];
  for (const id of ids) {
    const s = pending.get(id);
    if (!s) { refused.push({ id, error: GONE }); continue; }
    if (!s.applicable) { refused.push({ id, error: BLOCKED_WORDS }); continue; }
    try {
      const r = await arbiter.resolvePolicyProposal(id, "approved", "dashboard");
      applied.push({ id, changeId: r.changeId ?? null });
    } catch (err) {
      if (isAdminBoundaryError(err)) {
        return json(res, 503, { error: String((err as Error).message), applied, refused });
      }
      refused.push({ id, error: String((err as Error)?.message ?? err) });
    }
  }
  try {
    json(res, 200, { applied, refused, ...(await listing(deps)) });
  } catch {
    json(res, 200, { applied, refused, suggestions: null, count: null });
  }
}

export async function postDismiss(deps: SuggestionRouteDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { arbiter } = deps;
  if (!arbiter.dismissSuggestion || !arbiter.policySuggestions) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { id?: unknown } | undefined;
  const id = body?.id;
  if (typeof id !== "string" || !SUGGESTION_ID.test(id)) return json(res, 400, { error: "id must be a suggestion id" });
  try {
    const r = await arbiter.dismissSuggestion(id, "dashboard");
    json(res, 200, { dismissed: r.suggestion.id, status: r.suggestion.status, ...(await listing(deps)) });
  } catch (err) {
    json(res, failStatus(err), { error: String((err as Error)?.message ?? err) });
  }
}

// ── the model picker (plan 14 §14.5, §14.11; dashboard.md §4.25t) ──────────

const NOT_OFFERED_ERROR = "Asking a model to suggest rules is not offered yet.";
const DIGEST = /^[0-9a-f]{64}$/;

/** The roots of a model run: the typed folder, else the folders the
 *  recorded sessions worked in (as for Scan). */
async function modelRoots(deps: SuggestionRouteDeps, raw: unknown, home: string): Promise<string[] | { error: string; needsRoot?: true }> {
  if (raw !== undefined && raw !== null && raw !== "") {
    if (typeof raw !== "string") return { error: "root must be a folder path" };
    const r = resolveRoot(raw, home);
    return r === null ? { error: "Give the folder as a full path, starting with / or ~." } : [r];
  }
  const roots = (await deps.workspaces().catch(() => [])).slice(0, SCAN_ROOTS_MAX);
  return roots.length === 0 ? { error: NO_WORKSPACE, needsRoot: true } : roots;
}

export async function postModelPreview(deps: SuggestionRouteDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!modelOffered(deps)) return json(res, 403, { error: NOT_OFFERED_ERROR });
  const { arbiter } = deps;
  if (!arbiter.modelSuggestPreview) return json(res, 501, { error: UNSUPPORTED });
  const home = homeOf(deps);
  const body = (await readJson(req)) as { tier?: unknown; endpoint?: unknown; root?: unknown; includeHome?: unknown } | undefined;
  if (body === undefined || body === null || typeof body !== "object") return json(res, 400, { error: "invalid JSON body" });
  if (body.tier !== "names" && body.tier !== "contents") return json(res, 400, { error: "tier must be names or contents" });
  if (body.endpoint !== undefined && (typeof body.endpoint !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(body.endpoint))) {
    return json(res, 400, { error: "endpoint must be the name of a model in Settings › Models" });
  }
  if (body.includeHome !== undefined && typeof body.includeHome !== "boolean") return json(res, 400, { error: "includeHome must be true or false" });
  const includeHome = body.includeHome === true;
  if (includeHome && !posix.isAbsolute(home)) return json(res, 400, { error: NO_HOME });
  const roots = await modelRoots(deps, body.root, home);
  if (!Array.isArray(roots)) return json(res, 400, roots);
  try {
    const p = await arbiter.modelSuggestPreview(roots, {
      tier: body.tier, home, ...(typeof body.endpoint === "string" ? { endpoint: body.endpoint } : {}), ...(includeHome ? { includeHome: true } : {}),
    });
    json(res, 200, { preview: modelPreviewVM(p, home) });
  } catch (err) {
    const msg = String((err as Error)?.message ?? err);
    json(res, isAdminBoundaryError(err) ? 503 : /already running|in progress/.test(msg) ? 409 : 422, { error: modelErrorWords(msg) });
  }
}

export async function postModelSend(deps: SuggestionRouteDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!modelOffered(deps)) return json(res, 403, { error: NOT_OFFERED_ERROR });
  const { arbiter } = deps;
  if (!arbiter.modelSuggest || !arbiter.policySuggestions) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as { digest?: unknown; tier?: unknown } | undefined;
  if (typeof body?.digest !== "string" || !DIGEST.test(body.digest)) return json(res, 400, { error: "digest must be a preview's digest" });
  const tier = body.tier === "contents" ? "contents" as const : "names" as const;
  let run: ModelRunWire;
  try {
    run = await arbiter.modelSuggest(body.digest, { waitMs: deps.modelWaitMs ?? MODEL_WAIT_MS });
  } catch (err) {
    const msg = String((err as Error)?.message ?? err);
    return json(res, isAdminBoundaryError(err) ? 503 : /look again|no longer held/.test(msg) ? 410 : 409, { error: modelErrorWords(msg) });
  }
  try {
    json(res, 200, { run: modelRunVM(run, tier), ...(await listing(deps)) });
  } catch {
    json(res, 200, { run: modelRunVM(run, tier), suggestions: null, count: null });
  }
}
