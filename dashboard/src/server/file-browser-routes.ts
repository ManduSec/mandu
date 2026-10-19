/**
 * server/file-browser-routes — the Rules page's file browser (dashboard.md
 * §4.25m):
 *
 *   GET  /api/files/list?path=<abs or ~>&offset=N
 *        → one folder's entries (names and kinds only, never contents), each
 *          with the label a read would get today and where it came from
 *   POST /api/files/labels { changes, expected?, reason? }
 *        each change { path, level, bindings?, recursive?, version? }
 *        → { applied: true, changeId, page }          done (undo in History)
 *        → 409 { stale: true, changed, error }        a rule it was made
 *                                                     from changed: nothing saved
 *        → { applied: false, confirm: true, expected, loosens }
 *                                                     it would loosen protection:
 *                                                     ask, then send again with `expected`
 *
 * LISTING. The dashboard runs as the person, so it can list what they can
 * list; seeing the dashboard is already the person's authority (the user's
 * call, 2026-09-28), so remote viewers browse too. What the route guards is
 * the OTHER local caller: a GET is open to any same-host process, the agent's
 * included, so this one is served only to the admin session with the CSRF
 * header (server.ts), like a labeling act. It never opens a file: `readdir`
 * and, for a symlink, a `stat` of its target to say whether it is a folder.
 * A label it cannot read (arbiter down) is served as unknown, never as "No
 * label".
 *
 * SAVE. The browser names paths and levels; the edits are planned HERE
 * (view-model/file-browser.ts planFileChanges). A path whose rule of its own
 * lives in the page's store (labels made before they moved to policy.yaml;
 * that store wins on the same path) is changed there, in place; every other
 * change is one policy.yaml change through the same human-apply sequence as
 * the Rules page's row buttons (applyAsHuman): a change that loosens
 * protection is applied only when the person confirmed exactly those
 * loosenings. Behind the server's global mutating gate (CSRF + admin session).
 *
 * A label chosen rewrites the path's rule whole (`lock-path` replaces its
 * level, hosts and reach), carrying over what the page read (the hosts in
 * the row, the rule's reach). So the listing gives each entry the version
 * of its path's own rule (the absent version when it has none), the page
 * sends it back with the change, and each policy.yaml edit names its rule
 * with it (`basedOn`, policy-surface.md §8.4.6 "An item-level version"): a
 * rule changed somewhere else since (another tab, a hand edit, an *Always*
 * in Approvals) refuses the save, 409 `stale`, nothing written, instead of
 * being put back to what the page read. A change that names no version (a
 * typed path, a symlink's target, an older page) names the version this
 * route's own read finds just before it proposes. An arbiter that answers
 * no versions is sent no change that names one (501).
 */
import { lstatSync, readdirSync, readlinkSync, realpathSync, statSync, type Dirent } from "node:fs";
import { homedir } from "node:os";
import { posix } from "node:path";
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import { filePaths } from "./path-kinds.js";
import { applyAsHuman } from "./policy-assistant-routes.js";
import { RULES_PAGE_APPROVER } from "./rule-action-routes.js";
import type { PolicyDocArbiter } from "./policy-doc-routes.js";
import type { SecretsArbiter } from "./secrets-routes.js";
import { relaxKey } from "../policy-assistant.js";
import type { HomeTextPart } from "../view-model/ask-words.js";
import {
  fileLabel,
  fileStaleWords,
  levelParts,
  levelRank,
  levelWords,
  looseningWords,
  pageLooseningWords,
  pathItemKey,
  pathVersionOf,
  planFileChanges,
  tildePath,
  whyWords,
  type FileLabelVM,
  type LockEdit,
  type PageLabel,
  type PathLevelsEntryWire,
  type WhyPathWire,
} from "../view-model/file-browser.js";

/** Entries per page of one folder. */
export const LIST_PAGE = 500;

export interface FileEntryVM {
  name: string;
  /** Absolute path (what a rule is written on). */
  path: string;
  /** `~/…` spelling for display. */
  display: string;
  kind: "dir" | "file" | "other";
  /** A symlink: where it points, `~`-shortened. A link to a folder is `dir`. */
  link: string | null;
  /** A symlink: the real file or folder it ends at (all links followed), or
   *  null when it points nowhere. A rule chosen for the link is written on
   *  this path too (dashboard.md §4.25m "Symlinks"). */
  target: string | null;
  /** The label of `target`, when it differs from the link's own. */
  targetLabel: FileLabelVM | null;
  /** The label a read would get today; null when it could not be read. */
  label: FileLabelVM | null;
  /** For a folder: how many rules of the person's are on paths inside it. */
  inside: number;
  /** The version of this path's own rule in policy.yaml (the absent version
   *  when it has none), sent back with a change made to it; null when the
   *  service sends no versions. */
  version: string | null;
}

export interface FileListVM {
  path: string;
  display: string;
  home: string;
  parent: string | null;
  crumbs: Array<{ name: string; path: string }>;
  /** The folder's own label (null when unreadable). */
  self: FileLabelVM | null;
  entries: FileEntryVM[];
  total: number;
  offset: number;
  more: boolean;
  /** "ok", or "unknown" when the labels could not be read. */
  labels: "ok" | "unknown";
  labelError?: string;
  /** Is protection (the confidentiality axis) on? null when unknown. */
  axis: boolean | null;
}

export interface FileBrowserDeps {
  secrets?: SecretsArbiter;
  policyDoc?: PolicyDocArbiter;
  /** Test seam: the HOME `~` means (default os.homedir()). */
  home?: string;
}

const GLOB = /[*?[]/;

/** A written path as its absolute spelling: `~` expanded, `.`/`..` folded, no
 *  trailing slash. A pattern keeps its glob (`**` stays leading). null when it
 *  is neither absolute, `~`-anchored nor a `**` pattern. */
function resolveWrittenPath(raw: string, home: string): string | null {
  let p = raw.trim();
  if (p === "") return null;
  if (p.startsWith("**/")) return p;
  if (p === "~") p = home;
  else if (p.startsWith("~/")) p = posix.join(home, p.slice(2));
  if (!p.startsWith("/")) return null;
  p = posix.normalize(p);
  return p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
}

/** The breadcrumb trail, with `~` standing for HOME when the folder is inside it. */
function crumbsFor(abs: string, home: string): Array<{ name: string; path: string }> {
  const out: Array<{ name: string; path: string }> = [];
  let start = "/";
  let rest = abs;
  if (home !== "/" && (abs === home || abs.startsWith(home + "/"))) {
    out.push({ name: "~", path: home });
    start = home;
    rest = abs.slice(home.length);
  } else {
    out.push({ name: "/", path: "/" });
  }
  let at = start;
  for (const seg of rest.split("/").filter(Boolean)) {
    at = posix.join(at, seg);
    out.push({ name: seg, path: at });
  }
  return out;
}

type Kind = { kind: FileEntryVM["kind"]; link: string | null; target: string | null };

function kindOf(dir: string, d: Dirent): Kind {
  if (d.isDirectory()) return { kind: "dir", link: null, target: null };
  if (d.isFile()) return { kind: "file", link: null, target: null };
  if (d.isSymbolicLink()) {
    const at = posix.join(dir, d.name);
    let link: string | null = null;
    try { link = realpathish(at); } catch { link = null; }
    try {
      const st = statSync(at);
      let target: string | null = null;
      try { target = realpathSync(at); } catch { target = null; }
      return { kind: st.isDirectory() ? "dir" : st.isFile() ? "file" : "other", link, target };
    } catch {
      return { kind: "other", link, target: null }; // a broken link
    }
  }
  return { kind: "other", link: null, target: null };
}

/** A typed path's symlink target (all links followed), or null. */
function symlinkTarget(abs: string): string | null {
  try {
    if (!lstatSync(abs).isSymbolicLink()) return null;
    return realpathSync(abs);
  } catch {
    return null;
  }
}

/** Where a symlink points, as written (readlink), resolved against its folder. */
function realpathish(at: string): string {
  const t = readlinkSync(at);
  return t.startsWith("/") ? t : posix.normalize(posix.join(posix.dirname(at), t));
}

/** The folder's entries, sorted folders first and then by name; one page. */
function listFolder(abs: string, offset: number): { entries: Array<{ name: string; path: string } & Kind>; total: number } {
  const dirents = readdirSync(abs, { withFileTypes: true });
  const all = dirents.map((d) => ({ name: d.name, path: posix.join(abs, d.name), ...kindOf(abs, d) }));
  all.sort((a, b) => (a.kind === "dir" ? 0 : 1) - (b.kind === "dir" ? 0 : 1) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { entries: all.slice(offset, offset + LIST_PAGE), total: all.length };
}

/** The person's rules on literal paths (policy.yaml and the page's store). */
async function ruleState(secrets: SecretsArbiter | undefined): Promise<{ literal: string[]; page: PageLabel[] } | null> {
  if (!secrets) return null;
  try {
    const st = await secrets.confidentialityState();
    const labels = st.labels ?? [];
    return {
      literal: labels.filter((l) => !l.glob && !GLOB.test(l.path)).map((l) => l.path),
      page: labels.filter((l) => l.source !== "policy-file" && !l.glob).map((l) => ({ path: l.path, level: l.level, bindings: l.bindings, recursive: l.recursive })),
    };
  } catch {
    return null;
  }
}

export async function getFileList(deps: FileBrowserDeps, url: string, res: ServerResponse): Promise<void> {
  const home = deps.home ?? homedir();
  const params = new URLSearchParams(url.split("?")[1] ?? "");
  const abs = resolveWrittenPath(params.get("path") ?? "~", home);
  if (abs === null || abs.startsWith("**")) {
    return json(res, 400, { error: "Give a folder path starting with / or ~." });
  }
  const offset = Math.max(0, Math.min(Number.parseInt(params.get("offset") ?? "0", 10) || 0, 10_000_000));
  let listed: ReturnType<typeof listFolder>;
  try {
    listed = listFolder(abs, offset);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return json(res, 404, { error: "That folder does not exist. Use ~ to go to your home folder.", path: abs });
    if (code === "ENOTDIR") return json(res, 400, { error: "That is a file, not a folder.", path: abs, file: true });
    if (code === "EACCES" || code === "EPERM") return json(res, 403, { error: "You do not have permission to open this folder.", path: abs });
    return json(res, 500, { error: `could not list the folder: ${(err as Error).message}` });
  }

  // Each entry's own rule's version (§8.4.6), read BEFORE the labels: a
  // rule that changes between the two reads is shown as it is now with the
  // version from before, so its save is refused rather than let through.
  // Best effort: without it the entries carry none, and a save names the
  // version the save's own read finds.
  const versions = typeof deps.policyDoc?.policyDocument === "function" && deps.secrets?.pathLevels ? await deps.policyDoc.policyDocument().catch(() => null) : null;
  let byPath: Map<string, PathLevelsEntryWire> | null = null;
  let axis: boolean | null = null;
  let labelError: string | undefined;
  if (deps.secrets?.pathLevels) {
    try {
      const targets = listed.entries.map((e) => e.target).filter((t): t is string => t !== null);
      const r = await deps.secrets.pathLevels([...new Set([abs, ...listed.entries.map((e) => e.path), ...targets])], home);
      byPath = new Map(r.levels.map((l) => [l.path, l]));
      axis = r.axis;
    } catch (err) {
      labelError = isAdminBoundaryError(err) ? String((err as Error).message) : `the protection service did not answer (${(err as Error).message})`;
    }
  } else {
    labelError = deps.secrets ? "this Mandu service cannot read labels for the file browser; restart the Mandu stack on the current build" : "the protection service is not connected";
  }
  const rules = byPath ? await ruleState(deps.secrets) : null;
  const label = (p: string): FileLabelVM | null => {
    const e = byPath?.get(p);
    return e ? fileLabel(e, home) : null;
  };
  const differs = (a: FileLabelVM | null, b: FileLabelVM | null): FileLabelVM | null =>
    b !== null && (a === null || a.level !== b.level || a.bindings.join() !== b.bindings.join()) ? b : null;
  const inside = (dir: string): number => (rules ? rules.literal.filter((r) => r.startsWith(dir + "/")).length : 0);

  const vm: FileListVM = {
    path: abs,
    display: tildePath(abs, home),
    home,
    parent: abs === "/" ? null : posix.dirname(abs),
    crumbs: crumbsFor(abs, home),
    self: label(abs),
    entries: listed.entries.map((e) => ({
      name: e.name,
      path: e.path,
      display: tildePath(e.path, home),
      kind: e.kind,
      link: e.link === null ? null : tildePath(e.link, home),
      target: e.target,
      targetLabel: e.target === null ? null : differs(label(e.path), label(e.target)),
      label: label(e.path),
      inside: e.kind === "dir" ? inside(e.path) : 0,
      version: byPath ? pathVersionOf(versions, e.path) : null,
    })),
    total: listed.total,
    offset,
    more: offset + listed.entries.length < listed.total,
    labels: byPath ? "ok" : "unknown",
    ...(labelError ? { labelError } : {}),
    axis,
  };
  json(res, 200, vm);
}

// ── What a change does (dashboard.md §4.25m "Impact") ───────────────────────

/** How much of the disk one preview reads: file names only, never contents. */
export const SCAN_MAX = 5000;
const SCAN_DEPTH = 8;
const IMPACT_LIST = 50;

export interface ImpactFileVM {
  path: string;
  display: string;
  before: string;
  after: string;
  /** `before` and `after` with each host a code (dashboard.md §4.25u). */
  beforeParts: HomeTextPart[];
  afterParts: HomeTextPart[];
  /** Less protected afterwards (a weaker level, or a new place it may go). */
  weaker: boolean;
}

export interface ImpactVM {
  /** Files whose label was compared. */
  scanned: number;
  /** The scan stopped at its limit: there may be more. */
  truncated: boolean;
  changed: number;
  weaker: number;
  /** Changed files, the weaker ones first, at most 50. */
  files: ImpactFileVM[];
  /** For each rule that decides files it did not before (a pattern, a
   *  folder): how many, and a few of them. Keyed by the rule's path or
   *  pattern as the arbiter names it. */
  decidedBy: Record<string, { count: number; sample: string[] }>;
}

/** Files under `root` (itself when it is a file), breadth first, at most
 *  SCAN_DEPTH folders down and SCAN_MAX in all; symlinked folders are not
 *  followed. Only names are read. */
function walkFiles(root: string, into: Set<string>): boolean {
  let st;
  try { st = lstatSync(root); } catch { return false; }
  if (!st.isDirectory()) {
    if (into.size >= SCAN_MAX) return true;
    into.add(root);
    return false;
  }
  let level = [root];
  for (let depth = 0; depth <= SCAN_DEPTH && level.length > 0; depth++) {
    const next: string[] = [];
    for (const dir of level) {
      let ents: Dirent[];
      try { ents = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
      for (const d of ents) {
        const p = posix.join(dir, d.name);
        if (d.isDirectory()) next.push(p);
        else if (d.isFile() || d.isSymbolicLink()) {
          if (into.size >= SCAN_MAX) return true;
          into.add(p);
        }
      }
    }
    level = next;
  }
  return level.length > 0;
}

function bindingsWider(after: readonly string[], before: readonly string[]): boolean {
  return after.some((b) => !before.includes(b));
}

/** Compare every scanned file's label now and under `edits` (the arbiter's
 *  own derivation both times: `pathLevels` and `pathLevels withEdits`). */
async function computeImpact(
  secrets: SecretsArbiter,
  edits: readonly LockEdit[],
  folder: string | null,
  home: string,
): Promise<ImpactVM | null> {
  if (!secrets.pathLevels || edits.length === 0) return null;
  const paths = new Set<string>();
  let truncated = false;
  for (const e of edits) {
    const root = GLOB.test(e.path) ? folder : e.path;
    if (root !== null) truncated = walkFiles(root, paths) || truncated;
  }
  const all = [...paths];
  const out: ImpactVM = { scanned: all.length, truncated, changed: 0, weaker: 0, files: [], decidedBy: {} };
  const changed: ImpactFileVM[] = [];
  for (let i = 0; i < all.length; i += 1000) {
    const chunk = all.slice(i, i + 1000);
    const [now, then] = await Promise.all([secrets.pathLevels(chunk, home), secrets.pathLevels(chunk, home, edits)]);
    chunk.forEach((p, j) => {
      const a = now.levels[j]!;
      const b = then.levels[j]!;
      if (b.rule !== a.rule && b.rule !== null && b.rule.startsWith("label:")) {
        const via = b.rule.slice("label:".length);
        const slot = (out.decidedBy[via] ??= { count: 0, sample: [] });
        slot.count++;
        if (slot.sample.length < 5) slot.sample.push(tildePath(p, home));
      }
      if (a.level === b.level && a.bindings.join() === b.bindings.join()) return;
      const weaker = levelRank(b.level) < levelRank(a.level) || (b.level !== "public" && bindingsWider(b.bindings, a.bindings));
      changed.push({
        path: p, display: tildePath(p, home),
        before: levelWords(a.level, a.bindings), after: levelWords(b.level, b.bindings),
        beforeParts: levelParts(a.level, a.bindings), afterParts: levelParts(b.level, b.bindings),
        weaker,
      });
    });
  }
  out.changed = changed.length;
  out.weaker = changed.filter((c) => c.weaker).length;
  out.files = changed.sort((x, y) => Number(y.weaker) - Number(x.weaker) || (x.display < y.display ? -1 : 1)).slice(0, IMPACT_LIST);
  return out;
}

/** A rule chosen for a symlink is written on the file it points to as well:
 *  the kernel guard judges an open on the file it reaches, but a rule is
 *  matched on the path as written, so either spelling alone leaves the other
 *  uncovered. Only for a new rule; removing the link's rule leaves the
 *  target's (the safe direction). */
function withSymlinkTargets(raw: unknown, home: string): unknown {
  if (!Array.isArray(raw)) return raw;
  const out = [...raw];
  const named = new Set(raw.map((c) => (c && typeof c === "object" && typeof (c as { path?: unknown }).path === "string" ? resolveWrittenPath((c as { path: string }).path, home) : null)));
  for (const c of raw) {
    if (!c || typeof c !== "object") continue;
    const { path, level } = c as { path?: unknown; level?: unknown };
    if (typeof path !== "string" || level === null || level === undefined) continue;
    const abs = resolveWrittenPath(path, home);
    if (abs === null || GLOB.test(abs)) continue;
    const target = symlinkTarget(abs);
    if (target === null || target === abs || named.has(target)) continue;
    named.add(target);
    let dir = false;
    try { dir = statSync(target).isDirectory(); } catch { dir = false; }
    // The page read the link's rule, not the target's: the target's version
    // is the one the save's own read finds.
    const { version: _linkVersion, ...rest } = c as Record<string, unknown>;
    out.push({ ...rest, path: target, recursive: dir ? (c as { recursive?: unknown }).recursive ?? true : false });
  }
  return out;
}

/** POST /api/files/impact {changes, folder?} → { impact, page }: what the
 *  pending changes would do to the files under them (and, for a pattern,
 *  under `folder`), before anything is saved. Nothing is written. */
export async function postFileImpact(deps: FileBrowserDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { secrets } = deps;
  if (!secrets?.pathLevels) return json(res, 501, { error: UNSUPPORTED });
  const home = deps.home ?? homedir();
  const body = (await readJson(req)) as { changes?: unknown; folder?: unknown } | undefined;
  const rules = await ruleState(secrets);
  if (!rules) return json(res, 502, { error: "the protection service did not answer" });
  const plan = planFileChanges(withSymlinkTargets(body?.changes, home), (p) => resolveWrittenPath(p, home), rules.page);
  if (typeof plan === "string") return json(res, 400, { error: plan });
  const folder = typeof body?.folder === "string" ? resolveWrittenPath(body.folder, home) : null;
  try {
    const impact = await computeImpact(secrets, plan.edits, folder && !GLOB.test(folder) ? folder : null, home);
    json(res, 200, { impact, page: plan.page.length });
  } catch (err) {
    const msg = String((err as Error)?.message ?? err);
    json(res, /withEdits/.test(msg) ? 422 : isAdminBoundaryError(err) ? 503 : 502, { error: msg });
  }
}

// ── Why this label (dashboard.md §4.25m "Why") ──────────────────────────────

/** GET /api/files/why?path=… → { why }: everything the rules say about one
 *  file, in the page's words (the arbiter's `whyPath`, plus the programs that
 *  read the real file). Served like the listing: CSRF header + admin session. */
export async function getFileWhy(deps: FileBrowserDeps, url: string, res: ServerResponse): Promise<void> {
  const { secrets } = deps;
  if (!secrets?.whyPath || !secrets.pathLevels) return json(res, 501, { error: UNSUPPORTED });
  const home = deps.home ?? homedir();
  const params = new URLSearchParams(url.split("?")[1] ?? "");
  const abs = resolveWrittenPath(params.get("path") ?? "", home);
  if (abs === null || GLOB.test(abs)) return json(res, 400, { error: "Give a file or folder path starting with / or ~." });
  try {
    const [why, levels, state] = await Promise.all([
      secrets.whyPath(abs, home),
      secrets.pathLevels([abs], home),
      secrets.confidentialityState().catch(() => null),
    ]);
    const held = (state?.taintedProcesses ?? []).filter((t) => t.path === abs);
    let folder = false;
    try { folder = statSync(abs).isDirectory(); } catch { folder = false; }
    json(res, 200, { why: whyWords(why as WhyPathWire, levels.levels[0]!, held, home, folder) });
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `the protection service did not answer (${(err as Error).message})` });
  }
}

// ── Move the older rules into policy.yaml ───────────────────────────────────

/** POST /api/files/move-page-rules → { moved, changeId }: the rules made on
 *  this page before they lived in policy.yaml move there unchanged (the
 *  arbiter's `movePageLabels`, admin channel). Behind the global gate. */
export async function postMovePageRules(deps: FileBrowserDeps, res: ServerResponse): Promise<void> {
  const mover = deps.policyDoc?.movePageLabels;
  if (!mover) return json(res, 501, { error: UNSUPPORTED });
  try {
    json(res, 200, await mover("human:rules-page"));
  } catch (err) {
    // Refused because policy.yaml changed on disk, or because a hand edit
    // waiting in Approvals changes one of the same rules (policy-surface.md
    // §8.4.6): nothing moved, 409 with the arbiter's words.
    const msg = String((err as Error)?.message ?? err);
    json(res, isAdminBoundaryError(err) ? 503 : /changed on disk|waits for a human in Approvals/.test(msg) ? 409 : 502, { error: msg });
  }
}

const UNSUPPORTED = "this Mandu service cannot change rules from this page; restart the Mandu stack on the current build";
const MOVED = "Your rules changed while you were deciding. Nothing was changed. Try again.";
const REASON = "Changed in the file browser on the Rules page";

/** A stale refusal's answer: the rules that moved (`paths <key>` each, as
 *  the arbiter names them) in the page's words. */
function staleBody(changed: unknown, home: string): { error: string; stale: true; changed: string[] } {
  const list = Array.isArray(changed) ? changed.filter((c): c is string => typeof c === "string") : [];
  const displays = list.map((c) => tildePath(c.replace(/^paths /, "").replace(/^glob:/, ""), home));
  return { error: fileStaleWords(displays), stale: true, changed: list };
}

export async function postFileLabels(deps: FileBrowserDeps, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { secrets, policyDoc } = deps;
  if (!secrets || !policyDoc?.policyPreview || !policyDoc.policyPropose || !policyDoc.resolvePolicyProposal) {
    return json(res, 501, { error: UNSUPPORTED });
  }
  const home = deps.home ?? homedir();
  const body = (await readJson(req)) as { changes?: unknown; expected?: unknown; reason?: unknown; folder?: unknown } | undefined;
  const expected = body?.expected;
  if (expected !== undefined && (!Array.isArray(expected) || !expected.every((k) => typeof k === "string"))) {
    return json(res, 400, { error: "expected must be the list this route answered with" });
  }
  const why = typeof body?.reason === "string" ? body.reason.trim().replace(/\s+/g, " ").slice(0, 200) : "";

  const rules = await ruleState(secrets);
  if (!rules) return json(res, 502, { error: "the protection service did not answer; nothing was changed" });
  const plan = planFileChanges(withSymlinkTargets(body?.changes, home), (p) => resolveWrittenPath(p, home), rules.page);
  if (typeof plan === "string") return json(res, 400, { error: plan });

  // The rules the policy.yaml edits rewrite, named with their versions
  // (§8.4.6 "An item-level version"): the page's, else this read's.
  let basedOn: Array<{ section: string; key: string; version: string }> = [];
  if (plan.edits.length > 0) {
    let read;
    try {
      read = await policyDoc.policyDocument();
    } catch (err) {
      return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
    }
    const versioned = read.itemVersions !== undefined && typeof read.absentVersion === "string";
    // An arbiter that answers no versions could not refuse a stale write.
    if (!versioned && plan.versions.some((v) => v !== null)) return json(res, 501, { error: UNSUPPORTED });
    if (versioned) {
      // Changed since the page read it: said now, before any question.
      const moved = plan.edits.filter((e, i) => plan.versions[i] !== null && plan.versions[i] !== pathVersionOf(read, e.path));
      if (moved.length > 0) return json(res, 409, staleBody(moved.map((e) => `paths ${pathItemKey(e.path)}`), home));
      const seen = new Set<string>();
      basedOn = plan.edits.flatMap((e, i) => {
        const key = pathItemKey(e.path);
        if (seen.has(key)) return [];
        seen.add(key);
        return [{ section: "paths", key, version: plan.versions[i] ?? pathVersionOf(read, e.path)! }];
      });
    }
  }

  // What the person must confirm: the arbiter's own preview of the policy.yaml
  // edits, plus the page-store changes that loosen.
  let relax: Array<{ facet: string; subject: string }> = [];
  if (plan.edits.length > 0) {
    try {
      const preview = await policyDoc.policyPreview(plan.edits);
      if (!preview.ok) {
        const gone = preview.problems.some((p) => /\bno lock on\b/.test(p));
        return json(res, gone ? 409 : 422, gone
          ? { error: "One of these files has no rule of its own any more. Reload the folder.", problems: preview.problems }
          : { error: "this change is not valid", problems: preview.problems });
      }
      relax = preview.relaxations as typeof relax;
    } catch (err) {
      return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
    }
  }
  const keys = [...relax.map(relaxKey), ...plan.pageLoosens.map((l) => l.key)];
  if (expected === undefined && keys.length > 0) {
    // A rule reaching everything inside a path that is a file is worded as
    // that file (path-kinds.ts; words only: the keys asked are the same).
    const files = await filePaths([...plan.edits.filter((e) => e.op === "lock-path").map((e) => e.path), ...plan.pageLoosens.map((l) => l.subject)]);
    const loosens = [
      ...relax.map((r) => looseningWords(r, plan.edits, home, files)),
      ...plan.pageLoosens.map((l) => pageLooseningWords(l, home, files)),
    ];
    // The files it reaches, named (a folder made weaker covers the built-in
    // secrets inside it). Best effort: a scan that fails leaves the list off.
    const folder = typeof body?.folder === "string" ? resolveWrittenPath(body.folder, home) : null;
    const impact = await computeImpact(secrets, plan.edits, folder && !GLOB.test(folder) ? folder : null, home).catch(() => null);
    return json(res, 200, { applied: false, confirm: true, expected: keys, loosens, impact });
  }
  const shown = new Set((expected as string[] | undefined) ?? []);
  if (plan.pageLoosens.some((l) => !shown.has(l.key))) return json(res, 409, { error: MOVED });

  let changeId: string | null = null;
  if (plan.edits.length > 0) {
    const r = await applyAsHuman(policyDoc, plan.edits, [...shown], {
      reason: why ? `${REASON}: ${why}` : REASON,
      requestedBy: "rules-page",
      approver: RULES_PAGE_APPROVER,
      moved: MOVED,
      ...(basedOn.length > 0 ? { basedOn } : {}),
    });
    if (r.status === 409 && r.body["stale"] === true) return json(res, 409, staleBody(r.body["changed"], home));
    if (r.status !== 200) return json(res, r.status, r.body);
    changeId = (r.body["changeId"] as string | null | undefined) ?? null;
  }
  let page = 0;
  try {
    for (const a of plan.page) {
      if (a.act === "remove") await secrets.removePathLabel(a.path);
      else await secrets.setPathLabel({ path: a.path, confidentiality: a.level, bindings: a.bindings, recursive: a.recursive });
      page++;
    }
  } catch (err) {
    const done = changeId ? "Your rules file was changed, and " : "";
    return json(res, isAdminBoundaryError(err) ? 503 : 502, {
      error: `${done}${page} of ${plan.page.length} rules made on this page earlier were changed before the protection service stopped answering: ${(err as Error).message}`,
      changeId,
    });
  }
  json(res, 200, { applied: true, changeId, page });
}
