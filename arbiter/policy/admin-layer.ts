/**
 * admin-layer — the organization's own `models:` and `perimeter:`, read-only to
 * the user (docs/design/confidentiality/model-endpoints.md §2
 * D5).
 *
 * Every `*.yaml` under `/etc/mandu/policy.d/` (sorted by file name), read
 * when the arbiter starts, before the user's `policy.yaml`, and again when a
 * file changes (the arbiter polls the directory with the policy file's own
 * interval, `adminLayerSignature`). An organization's configuration
 * management installs the files; Mandu needs no privilege to read them. The directory is a constant here: a build can change it, a
 * session cannot (no environment variable names it). Tests pass their own
 * directory to the ArbiterServer constructor (`adminPolicyDir`), which is not
 * reachable from a session either.
 *
 * What a file may set: `models:`, `perimeter:`, `models_locked: true`,
 * `sensitivity_labels:` (plan 14 §14.1: label GUIDs are the tenant's),
 * `prompt_filters:` (confidentiality-plan-15 §6: filters, actions and
 * exceptions, each filter or action optionally `locked: true`; merged in
 * prompt-filter/policy.ts `effectivePromptConfig`), `bwrap_path:` (the
 * bubblewrap Mandu runs in place of the one on PATH, read by
 * src/bwrap-path.ts; only its form is checked here; rootless-confinement-
 * ubuntu-2404.md §0.7) and `version: 1`. Nothing else: the rest of the law stays the user's. The
 * label mapping merges by (id, site) with the stricter level winning
 * (sensitivity-labels.ts `effectiveLabelMapping`), so a user file never
 * lowers what the organization mapped; it only adds or raises.
 *
 * Merging (`effectiveModels`): the administrator's entries come first, each
 * marked with its file. A user entry with the same name replaces it, and a
 * user entry `{ name, disabled: true }` removes it. With `models_locked: true`
 * (`adminLockProblems`, run by `validatePolicyDocument`, so by every writer:
 * a hand edit, the dashboard's Settings › Models, a raw document apply, an
 * approved proposal) the user may remove an administrator's entry and add
 * entries that are not `local: true`, and nothing else: adding a `local:
 * true` entry, or changing an administrator's entry's url, tls, local, helper
 * or allow_plain_http, is refused with "set by your administrator (<file>)".
 *
 * The administrator's `perimeter.networks` holds with or without the lock: a
 * user `perimeter:` may narrow them, never drop or widen them (the perimeter
 * is a fact about the organization, not a model default).
 *
 * Without the lock the administrator's entries are defaults the user may
 * change or remove, and without any file today's behaviour is unchanged.
 *
 * The administrator wins. When the layer changes under a user file that now
 * breaks it (a lock arrives, a perimeter narrows), the conflicting user
 * entries stay in the file but are not in force (`effectiveModels` leaves them
 * out), the arbiter says which (`adminLockProblems`, shown by Settings and
 * doctor), and it never refuses to start over one. A write is refused only
 * when it ADDS a conflict (policy-file-validate.ts, `tolerate`).
 *
 * What this does not stop: an employee with a shell who runs a modified
 * Mandu. It stops the user's own surfaces, the policy agent and an injected
 * agent from widening the list.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

import type { ModelEndpointEntry, PolicyFileConfig, SensitivityLabelEntry } from "./load-policy.js";
import { networksWithin } from "./model-perimeter.js";
import { checkPromptFilters, type AdminPromptFilters, type PromptFiltersConfig } from "../prompt-filter/policy.js";
import { adminBwrapLine } from "../src/bwrap-path.js";

/** The administrator's layer. A build may change it; nothing at run time can. */
export const ADMIN_POLICY_DIR = "/etc/mandu/policy.d";

export interface AdminModel {
  readonly entry: ModelEndpointEntry;
  /** The file that set it (absolute). */
  readonly file: string;
}

/** One administrator's `sensitivity_labels:` entry, with its file. */
export interface AdminSensitivityLabel {
  readonly entry: SensitivityLabelEntry;
  readonly file: string;
}

export interface AdminLayer {
  /** The directory read (null: no layer was asked for). */
  readonly dir: string | null;
  /** The files that were read, sorted. */
  readonly files: readonly string[];
  readonly models: readonly AdminModel[];
  readonly perimeter: PolicyFileConfig["perimeter"] | null;
  readonly perimeterFile: string | null;
  /** `models_locked: true` in some file. */
  readonly locked: boolean;
  readonly lockFile: string | null;
  /** Plan 14 §14.1: the organization's label mapping (absent in a layer
   *  built before it: read as none). */
  readonly sensitivityLabels?: readonly AdminSensitivityLabel[];
  /** Plan 15 §6: each file's `prompt_filters:` in file order (absent in a
   *  layer built before it: read as none). */
  readonly promptFilters?: readonly AdminPromptFilters[];
}

export const NO_ADMIN_LAYER: AdminLayer = Object.freeze({
  dir: null, files: Object.freeze([]), models: Object.freeze([]), perimeter: null, perimeterFile: null, locked: false, lockFile: null,
  sensitivityLabels: Object.freeze([]),
  promptFilters: Object.freeze([]),
});

/** An administrator's file that cannot be used: the arbiter refuses to start. */
export class AdminLayerError extends Error {
  constructor(readonly dir: string, readonly problems: readonly string[]) {
    super(`your administrator's policy in ${dir} cannot be used:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
    this.name = "AdminLayerError";
  }
}

const ADMIN_KEYS = new Set(["version", "models", "perimeter", "models_locked", "sensitivity_labels", "prompt_filters", "bwrap_path"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * Read the layer. A missing directory is no layer. `validate` checks one
 * file's `{ models, perimeter }` with the user file's own rules (passed in
 * to keep this module free of the validator's imports). Throws
 * {@link AdminLayerError} listing every problem.
 */
export function loadAdminLayer(dir: string | null, validate: (doc: PolicyFileConfig) => string[]): AdminLayer {
  if (dir === null || !existsSync(dir)) return { ...NO_ADMIN_LAYER, dir };
  const problems: string[] = [];
  let names: string[];
  try {
    names = readdirSync(dir).filter((n) => /\.ya?ml$/.test(n)).sort();
  } catch (err) {
    throw new AdminLayerError(dir, [`cannot list the directory: ${(err as Error).message}`]);
  }
  const files: string[] = [];
  const models: AdminModel[] = [];
  const byName = new Map<string, string>();
  let perimeter: PolicyFileConfig["perimeter"] | null = null;
  let perimeterFile: string | null = null;
  let locked = false;
  let lockFile: string | null = null;
  const sensitivityLabels: AdminSensitivityLabel[] = [];
  const labelAt = new Map<string, string>();
  const promptFilters: AdminPromptFilters[] = [];
  const promptAt = new Map<string, string>();
  for (const n of names) {
    const file = join(dir, n);
    try { if (!statSync(file).isFile()) continue; } catch { continue; }
    files.push(file);
    let doc: unknown;
    let text = "";
    try {
      text = readFileSync(file, "utf8");
      doc = yaml.load(text);
    } catch (err) {
      problems.push(`${file}: ${(err as Error).message.split("\n")[0]}`);
      continue;
    }
    if (doc === null || doc === undefined) continue;
    if (!isPlainObject(doc)) { problems.push(`${file}: must be a mapping with models, perimeter, models_locked, sensitivity_labels, prompt_filters and/or bwrap_path`); continue; }
    for (const k of Object.keys(doc)) {
      if (!ADMIN_KEYS.has(k)) problems.push(`${file}: '${k}' cannot be set here (an administrator's file sets models, perimeter, models_locked, sensitivity_labels, prompt_filters and bwrap_path; the rest of the policy is the user's)`);
    }
    if ("prompt_filters" in doc) {
      const pf: string[] = [];
      checkPromptFilters(doc.prompt_filters, "prompt_filters", pf, { admin: true });
      for (const p of pf) problems.push(`${file}: ${p}`);
      if (pf.length === 0) {
        // One file per filter id and per category: two files that both set
        // one would make the winner depend on file names.
        const c = doc.prompt_filters as PromptFiltersConfig;
        for (const id of Object.keys(c.filters ?? {})) {
          const was = promptAt.get(`f:${id}`);
          if (was !== undefined && was !== file) problems.push(`${file}: prompt_filters.filters.${id} is already set in ${was}`);
          promptAt.set(`f:${id}`, file);
        }
        for (const cat of Object.keys(c.actions ?? {})) {
          const was = promptAt.get(`a:${cat}`);
          if (was !== undefined && was !== file) problems.push(`${file}: prompt_filters.actions.${cat} is already set in ${was}`);
          promptAt.set(`a:${cat}`, file);
        }
        promptFilters.push(Object.freeze({ file, config: c }));
      }
    }
    if ("version" in doc && doc.version !== 1) problems.push(`${file}: version must be 1`);
    // `bwrap_path` (rootless-confinement-ubuntu-2404.md §0.7): the bubblewrap
    // Mandu runs in place of the one on PATH. The arbiter does not use it;
    // src/bwrap-path.ts reads it (the launcher, the git sandbox, the
    // plugins) by line, and also requires the file and the binary to be
    // root's alone. Checked here for form, by that same line reader, so a
    // value the two would read differently stops the arbiter instead.
    if ("bwrap_path" in doc) {
      const line = adminBwrapLine(text);
      if (typeof doc.bwrap_path !== "string" || line.kind !== "path" || line.path !== doc.bwrap_path) {
        problems.push(`${file}: bwrap_path must be one absolute path on its own line (bwrap_path: /opt/bubblewrap/bin/bwrap)`);
      }
    }
    if ("models_locked" in doc) {
      if (typeof doc.models_locked !== "boolean") problems.push(`${file}: models_locked must be true or false`);
      else if (doc.models_locked) { locked = true; lockFile ??= file; }
    }
    const sub: PolicyFileConfig = {};
    if ("models" in doc) sub.models = doc.models as ModelEndpointEntry[];
    if ("perimeter" in doc) sub.perimeter = doc.perimeter as PolicyFileConfig["perimeter"];
    if ("sensitivity_labels" in doc) sub.sensitivity_labels = doc.sensitivity_labels as SensitivityLabelEntry[];
    for (const p of validate(sub)) problems.push(`${file}: ${p}`);
    if (Array.isArray(doc.sensitivity_labels)) {
      for (const e of doc.sensitivity_labels as unknown[]) {
        if (!isPlainObject(e) || typeof e.id !== "string") continue;
        const k = `${labelGuid(e.id)}|${typeof e.site === "string" ? labelGuid(e.site) : ""}`;
        const was = labelAt.get(k);
        if (was !== undefined && was !== file) { problems.push(`${file}: sensitivity_labels: ${e.id} is already mapped in ${was}`); continue; }
        labelAt.set(k, file);
        sensitivityLabels.push(Object.freeze({ entry: e as unknown as SensitivityLabelEntry, file }));
      }
    }
    if (Array.isArray(doc.models)) {
      for (const e of doc.models as unknown[]) {
        if (!isPlainObject(e) || typeof e.name !== "string") continue;
        if ("disabled" in e) { problems.push(`${file}: models: '${e.name}': disabled is for the user's file (leave the entry out instead)`); continue; }
        const was = byName.get(e.name);
        if (was !== undefined) { problems.push(`${file}: models: '${e.name}' is already set in ${was}`); continue; }
        byName.set(e.name, file);
        models.push(Object.freeze({ entry: e as unknown as ModelEndpointEntry, file }));
      }
    }
    if ("perimeter" in doc) {
      if (perimeterFile !== null) problems.push(`${file}: perimeter is already set in ${perimeterFile} (set it in one file)`);
      else { perimeter = doc.perimeter as PolicyFileConfig["perimeter"]; perimeterFile = file; }
    }
  }
  if (problems.length > 0) throw new AdminLayerError(dir, problems);
  return Object.freeze({
    dir, files: Object.freeze(files), models: Object.freeze(models), perimeter, perimeterFile, locked, lockFile,
    sensitivityLabels: Object.freeze(sensitivityLabels),
    promptFilters: Object.freeze(promptFilters),
  });
}

/** A GUID as the duplicate check compares it (lowercase, no braces). */
function labelGuid(v: string): string {
  const s = v.trim().toLowerCase();
  return s.startsWith("{") && s.endsWith("}") ? s.slice(1, -1) : s;
}

/**
 * What the directory holds, cheaply: each `*.yaml` name with its size, mtime
 * and inode ("" when the directory is absent). A changed signature makes the
 * arbiter read the layer again.
 */
export function adminLayerSignature(dir: string | null): string {
  if (dir === null) return "";
  let names: string[];
  try {
    names = readdirSync(dir).filter((n) => /\.ya?ml$/.test(n)).sort();
  } catch {
    return existsSync(dir) ? "unreadable" : "";
  }
  return JSON.stringify(names.map((n) => {
    try {
      const st = statSync(join(dir, n));
      return [n, st.size, st.mtimeMs, st.ino];
    } catch {
      return [n];
    }
  }));
}

let current: AdminLayer = NO_ADMIN_LAYER;

/** The layer in force (the arbiter sets it at start and when a file changes). */
export function getAdminLayer(): AdminLayer {
  return current;
}

export function setAdminLayer(layer: AdminLayer): AdminLayer {
  current = layer;
  return layer;
}

/** Does the layer set anything? */
export function hasAdminLayer(layer: AdminLayer): boolean {
  return layer.models.length > 0 || layer.perimeter !== null || layer.locked;
}

/** A merged entry: the user's, or the administrator's (with its file). */
export type EffectiveModelEntry = ModelEndpointEntry & { readonly adminFile?: string };

/** The fields the lock protects on an administrator's entry. */
const LOCKED_FIELDS = ["url", "tls", "local", "helper", "allow_plain_http"] as const;

function sameValue(a: unknown, b: unknown): boolean {
  const norm = (v: unknown): unknown => (v === false ? undefined : v);
  return JSON.stringify(canonical(norm(a))) === JSON.stringify(canonical(norm(b)));
}
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (isPlainObject(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  return v;
}

/** Does a user entry keep every locked field of the administrator's entry? */
function keepsLockedFields(user: ModelEndpointEntry, admin: ModelEndpointEntry): boolean {
  return LOCKED_FIELDS.every((k) => sameValue((user as unknown as Record<string, unknown>)[k], (admin as unknown as Record<string, unknown>)[k]));
}

/**
 * The models and perimeter in force for a user document under the layer.
 * Pure. With no layer: the document's own, unchanged. The administrator wins
 * every conflict (a user file written before the layer changed): under the
 * lock, a user `local: true` entry and a user entry that changes an
 * administrator's locked fields are left out; a second helper beside the
 * administrator's loses the mark; a user perimeter that is not a narrowing is
 * replaced by the administrator's. `adminLockProblems` names each.
 */
export function effectiveModels(doc: PolicyFileConfig | null, layer: AdminLayer): { models: EffectiveModelEntry[]; perimeter: PolicyFileConfig["perimeter"] | undefined } {
  const userModels = Array.isArray(doc?.models) ? doc!.models : [];
  if (!hasAdminLayer(layer)) {
    return { models: userModels.filter((m) => !(isPlainObject(m) && (m as { disabled?: unknown }).disabled === true)), perimeter: doc?.perimeter };
  }
  const out: EffectiveModelEntry[] = layer.models.map((m) => ({ ...m.entry, adminFile: m.file }));
  for (const u of userModels) {
    if (!isPlainObject(u) || typeof u.name !== "string") continue;
    const at = out.findIndex((m) => m.name === u.name);
    if ((u as { disabled?: unknown }).disabled === true) {
      if (at >= 0 && out[at]!.adminFile !== undefined) out.splice(at, 1);
      continue;
    }
    const admin = layer.models.find((m) => m.entry.name === u.name);
    if (layer.locked) {
      // Not in force under the lock (a conflict): the administrator's entry,
      // if any, stays as the administrator wrote it.
      if (admin && !keepsLockedFields(u, admin.entry)) continue;
      if (!admin && u.local === true) continue;
    }
    // An override that keeps the locked fields is still the administrator's
    // entry (its file is named); one that changes them is the user's.
    const merged: EffectiveModelEntry = admin && keepsLockedFields(u, admin.entry) ? { ...u, adminFile: admin.file } : { ...u };
    if (at >= 0) out[at] = merged;
    else out.push(merged);
  }
  // One helper: the administrator's, when it names one.
  const isHelper = (m: EffectiveModelEntry): boolean => m.helper === true && m.local === true;
  if (out.some((m) => isHelper(m) && m.adminFile !== undefined)) {
    for (let i = 0; i < out.length; i++) {
      const m = out[i]!;
      if (isHelper(m) && m.adminFile === undefined) {
        const { helper: _dropped, ...rest } = m;
        out[i] = rest;
      }
    }
  }
  return { models: out, perimeter: effectivePerimeter(doc?.perimeter, layer) };
}

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((n): n is string => typeof n === "string") : [];
}

/** Is the user's `perimeter.networks` a narrowing of the administrator's?
 *  (An unusable CIDR is not.) */
function narrowsAdmin(user: readonly string[], admin: readonly string[]): boolean {
  try {
    return networksWithin(user, admin);
  } catch {
    return false;
  }
}

function effectivePerimeter(user: PolicyFileConfig["perimeter"] | undefined, layer: AdminLayer): PolicyFileConfig["perimeter"] | undefined {
  const admin = layer.perimeter ?? undefined;
  if (user === undefined || !isPlainObject(user)) return admin;
  if (admin === undefined) return user;
  // The user's networks when they narrow the administrator's (with or
  // without the lock), else the administrator's; the domains of both (words
  // only).
  const adminNets = admin.networks ? stringList(admin.networks) : null;
  const userNets = stringList(user.networks);
  const networks = adminNets === null ? user.networks : userNets.length > 0 && narrowsAdmin(userNets, adminNets) ? userNets : adminNets;
  const domains = [...new Set([...stringList(admin.domains), ...stringList(user.domains)])];
  return { ...(networks ? { networks } : {}), ...(domains.length > 0 ? { domains } : {}) };
}

/**
 * The lock, and the user entries that only make sense against the layer
 * (`disabled`). Problems in the validator's style, naming the file. Pure.
 */
export function adminLockProblems(doc: PolicyFileConfig | null, layer: AdminLayer): string[] {
  const out: string[] = [];
  const userModels = Array.isArray(doc?.models) ? (doc!.models as unknown[]) : [];
  const where = (file: string): string => `set by your administrator (${file})`;
  userModels.forEach((u, i) => {
    if (!isPlainObject(u) || typeof u.name !== "string") return;
    const admin = layer.models.find((m) => m.entry.name === u.name);
    const here = `models[${i}]`;
    if (u.disabled === true) {
      if (!admin) out.push(`${here}: '${u.name}' is not set by your administrator, so disabled: true turns nothing off; remove the entry instead`);
      return;
    }
    if (!layer.locked) return;
    if (admin) {
      if (!keepsLockedFields(u as unknown as ModelEndpointEntry, admin.entry)) {
        const changed = LOCKED_FIELDS.filter((k) => !sameValue(u[k], (admin.entry as unknown as Record<string, unknown>)[k]));
        out.push(`${here}: '${u.name}' is ${where(admin.file)}, and its ${changed.join(", ")} cannot be changed here; you can remove it (disabled: true)`);
      }
    } else if (u.local === true) {
      out.push(`${here}: '${u.name}' is local: true, and your own models are ${where(layer.lockFile ?? layer.dir ?? "")}: you can add outside models only (local: true is refused)`);
    }
  });
  if (isPlainObject(doc?.perimeter) && layer.perimeter?.networks) {
    const nets = stringList(doc!.perimeter!.networks);
    if (nets.length > 0 && !narrowsAdmin(nets, stringList(layer.perimeter.networks))) {
      out.push(`perimeter.networks: ${where(layer.perimeterFile ?? layer.dir ?? "")} as ${layer.perimeter.networks.join(", ")}; you can narrow it here, not widen it`);
    }
  }
  return out;
}

/** The administrator's layer as the `policyDocument` op answers it. */
export interface AdminLayerView {
  files: string[];
  locked: boolean;
  models: Array<Record<string, unknown>>;
  perimeter: PolicyFileConfig["perimeter"] | null;
  perimeterFile: string | null;
  /** Plan 14 §14.1: the organization's label mapping, each entry with its
   *  file (Settings › Sensitivity labels shows them as set by the
   *  administrator). */
  sensitivityLabels: Array<Record<string, unknown>>;
  /** Plan 15 §6: the organization's `prompt_filters:`, each with its file
   *  (the Prompt filters panel shows them as set by the administrator). */
  promptFilters: Array<{ file: string; config: PromptFiltersConfig }>;
  /** The user's entries that are not in force because the administrator's
   *  layer wins (`adminLockProblems` of the document in force). */
  conflicts: string[];
  /** A changed layer that could not be read: the problems, and the layer in
   *  force is the one before it. Empty when the last read was good. */
  refused: string[];
}

/** The layer for the `policyDocument` op (plan 12 D5): the administrator's
 *  entries as their files spell them, the perimeter, the lock, the user's
 *  conflicts with it and a refused re-read. Empty when no layer is in force
 *  and nothing was refused. */
export function adminLayerView(layer: AdminLayer = getAdminLayer(), extra: { conflicts?: string[]; refused?: string[] } = {}): { admin?: AdminLayerView } {
  const refused = extra.refused ?? [];
  const labels = layer.sensitivityLabels ?? [];
  const prompt = layer.promptFilters ?? [];
  if (!hasAdminLayer(layer) && labels.length === 0 && prompt.length === 0 && refused.length === 0) return {};
  return {
    admin: {
      files: [...layer.files],
      locked: layer.locked,
      models: layer.models.map((m) => ({ ...(m.entry as unknown as Record<string, unknown>), file: m.file })),
      perimeter: layer.perimeter,
      perimeterFile: layer.perimeterFile,
      sensitivityLabels: labels.map((l) => ({ ...(l.entry as unknown as Record<string, unknown>), file: l.file })),
      promptFilters: prompt.map((p) => ({ file: p.file, config: p.config })),
      conflicts: extra.conflicts ?? [],
      refused,
    },
  };
}
