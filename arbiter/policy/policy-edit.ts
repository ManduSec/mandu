/**
 * policy-edit — typed edits to the law (docs/design/ui/policy-surface.md §8.4.1).
 *
 * Mandu-new (no reference origin). A model (the confined agent through the
 * `mandu-policy` MCP server, or the dashboard's setup assistant) never emits
 * YAML: it emits a list of {@link PolicyEdit}s, each of which renders to the
 * same plain row the Rules page shows. `applyEdits` is pure: it applies the
 * list to a COPY of the document, validates the result with the same
 * validator a hand-written file goes through, and returns either the new
 * document or every problem. One list, one verdict: it never applies part of
 * a list.
 *
 * The ops name INTENTIONS, not directions. Whether a list tightens (the data
 * plane may apply it) or relaxes (it waits for a human) is decided by
 * `policyDelta` over the two compiled laws, never by reading `op`; see
 * {@link evaluateEdits}.
 */
import { compilePolicy, type CompiledPolicy } from "./compiled-policy.js";
import type { BlobLockEntry, ModelEndpointEntry, ModelTlsEntry, PathLabelEntry, PolicyFileConfig, SensitivityLabelEntry, UserRuleEntry } from "./load-policy.js";
import { normalizeLabelPath } from "./path-labels.js";
import { hasGlobMeta } from "./path-glob.js";
import { validatePolicyDocument } from "./policy-file-validate.js";
import { getAdminLayer } from "./admin-layer.js";
import { BUILTIN_ORIGIN_DEFAULT } from "./policy-engine.js";
import { policyDelta, isTightening, type PolicyDelta } from "./policy-delta.js";
import type { InboundSpecId } from "./tool-inbound.js";
import type { PromptFiltersConfig } from "../prompt-filter/policy.js";

export type OriginKind = "url" | "dir" | "channel";

export type PolicyEdit =
  | { op: "lock-path"; path: string; level: "public" | "any-model" | "local-model" | "no-model"; bindings?: string[]; recursive?: boolean }
  | { op: "unlock-path"; path: string }
  // Plan 14 §8.2: a repository object by its id (`sha1:<40 hex>` |
  // `sha256:<64 hex>`), hidden from the agent in every repository.
  | { op: "lock-blob"; blob: string; level: "public" | "any-model" | "local-model" | "no-model"; note?: string }
  | { op: "unlock-blob"; blob: string }
  | { op: "trust-origin"; kind: OriginKind; pattern: string }
  | { op: "distrust-origin"; kind: OriginKind; pattern: string }
  | { op: "release"; id?: string; from?: { host: string }; to: { host: string }; mode: "allow" | "block" | "audit"; expires?: string | null; reason?: string }
  | { op: "retire-rule"; id: string }
  | { op: "set-disposition"; rule: string; mode: "ask" | "block" }
  | { op: "allow-connect"; host: string; port?: number | "*" }
  | { op: "remove-connect"; host: string; port?: number | "*" }
  | { op: "trust-command"; id: string; trustHelp: boolean }
  | { op: "tool-inbound"; tool: string; trust: "TRUSTED" | "UNTRUSTED" }
  | { op: "list"; name: string; add?: string[]; remove?: string[] }
  | ({ op: "add-model" } & ModelEditFields)
  | ({ op: "update-model" } & ModelEditFields)
  | { op: "remove-model"; name: string }
  | { op: "restore-model"; name: string }
  // Plan 14 §14.1: map a Purview sensitivity label (by GUID, optionally its
  // tenant) to a level, or remove the mapping. They change what the scans
  // suggest, never what is enforced.
  | { op: "map-sensitivity-label"; id: string; site?: string; name: string; level: "public" | "any-model" | "local-model" | "no-model" }
  | { op: "unmap-sensitivity-label"; id: string; site?: string }
  // Confidentiality plan 15 §6, §8.1: the prompt filter's switches. Made by
  // the developer dashboard's Prompt filters panel and hand edits; not
  // offered to a model. The monotonic split holds (policyDelta's
  // `prompt-filters` facet): turning a filter on or an action up applies,
  // the rest waits for a human.
  // `endpoint` (phase 3): a classifier plugin's `local: true` model; null removes it.
  | { op: "set-prompt-filter"; filter: string; on: boolean; on_error?: "block" | "pass" | null; endpoint?: string | null }
  | { op: "set-prompt-action"; category: string; action: "pass" | "log" | "redact" | "mask" | "ask" | "block" }
  | { op: "remove-prompt-action"; category: string }
  | { op: "add-prompt-exception"; category: string; match: string }
  | { op: "remove-prompt-exception"; category: string; match: string };

/** One `models:` entry as an edit carries it (plan 11 D2; the file's own
 *  spelling, `token_env` included). Checked by the validator's `checkModels`,
 *  never by a second copy of its rules here. */
export interface ModelEditFields {
  name: string;
  url: string;
  wire?: "anthropic" | "openai-chat";
  model?: string;
  local?: boolean;
  token_env?: string;
  helper?: boolean;
  allow_plain_http?: boolean;
  tls?: ModelTlsEntry;
}

export const POLICY_EDIT_OPS = [
  "lock-path", "unlock-path", "lock-blob", "unlock-blob", "trust-origin", "distrust-origin", "release", "retire-rule",
  "set-disposition", "allow-connect", "remove-connect", "trust-command", "tool-inbound", "list",
  "add-model", "update-model", "remove-model", "restore-model",
  "map-sensitivity-label", "unmap-sensitivity-label",
  "set-prompt-filter", "set-prompt-action", "remove-prompt-action", "add-prompt-exception", "remove-prompt-exception",
] as const;

const MODEL_FIELDS = ["name", "url", "wire", "model", "local", "token_env", "helper", "allow_plain_http", "tls"] as const;

export type PolicyEditOp = (typeof POLICY_EDIT_OPS)[number];

/** The ops over policy.yaml `models:` (plan 11 D2). They are part of the one
 *  grammar, but only a human's form (Settings › Models) and hand edits of the
 *  file change model endpoints: the policy agent (mandu-policy MCP, the data
 *  plane) and the dashboard's Describe box are never offered them and are
 *  refused them (policy-surface.md §8.4.3a, decision 2026-09-28). */
export const MODEL_EDIT_OPS: readonly PolicyEditOp[] = ["add-model", "update-model", "remove-model", "restore-model"];

/** The ops over policy.yaml `sensitivity_labels:` (plan 14 §14.1). Made by
 *  the person's form (Settings › Sensitivity labels) and hand edits; not
 *  offered to a model (the schema `policySchema` answers leaves them out).
 *  They are not refused on the data plane: the monotonic split holds (a
 *  new or raised mapping only adds suggestions a human reviews; anything
 *  else waits for a human). */
export const LABEL_EDIT_OPS: readonly PolicyEditOp[] = ["map-sensitivity-label", "unmap-sensitivity-label"];

/** The ops over policy.yaml `prompt_filters:` (confidentiality-plan-15 §6,
 *  §8.1). Made by the developer dashboard's Prompt filters panel and hand
 *  edits; not offered to a model (the human's prompt is the human's). Not
 *  refused on the data plane: the monotonic split holds. */
export const PROMPT_EDIT_OPS: readonly PolicyEditOp[] = ["set-prompt-filter", "set-prompt-action", "remove-prompt-action", "add-prompt-exception", "remove-prompt-exception"];

/** The ops a MODEL may propose (the schema `policySchema` answers). */
export const AGENT_EDIT_OPS: readonly PolicyEditOp[] = POLICY_EDIT_OPS.filter((op) => !MODEL_EDIT_OPS.includes(op) && !LABEL_EDIT_OPS.includes(op) && !PROMPT_EDIT_OPS.includes(op));

/**
 * One problem per model-endpoint edit in `edits`, naming only its index and
 * op (never a value the caller wrote). Empty when there is none, or when
 * `edits` is not a list (applyEdits reports that shape itself).
 */
export function modelEditProblems(edits: unknown, where = "this path"): string[] {
  if (!Array.isArray(edits)) return [];
  const out: string[] = [];
  edits.forEach((e, i) => {
    const op = isPlainObject(e) ? e.op : undefined;
    if (typeof op === "string" && (MODEL_EDIT_OPS as readonly string[]).includes(op)) {
      out.push(`edits[${i}] (${op}): model endpoints cannot be changed from ${where}; the user changes them in Settings › Models or in policy.yaml`);
    }
  });
  return out;
}

/** The keys each op accepts; any other key refuses the list. The schema
 *  generator (policy-edit-schema.ts) is pinned to these sets. */
export const EDIT_KEYS: Readonly<Record<(typeof POLICY_EDIT_OPS)[number], readonly string[]>> = {
  "lock-path": ["op", "path", "level", "bindings", "recursive"],
  "unlock-path": ["op", "path"],
  "lock-blob": ["op", "blob", "level", "note"],
  "unlock-blob": ["op", "blob"],
  "trust-origin": ["op", "kind", "pattern"],
  "distrust-origin": ["op", "kind", "pattern"],
  release: ["op", "id", "from", "to", "mode", "expires", "reason"],
  "retire-rule": ["op", "id"],
  "set-disposition": ["op", "rule", "mode"],
  "allow-connect": ["op", "host", "port"],
  "remove-connect": ["op", "host", "port"],
  "trust-command": ["op", "id", "trustHelp"],
  "tool-inbound": ["op", "tool", "trust"],
  list: ["op", "name", "add", "remove"],
  "add-model": ["op", ...MODEL_FIELDS],
  "update-model": ["op", ...MODEL_FIELDS],
  "remove-model": ["op", "name"],
  "restore-model": ["op", "name"],
  "map-sensitivity-label": ["op", "id", "site", "name", "level"],
  "unmap-sensitivity-label": ["op", "id", "site"],
  "set-prompt-filter": ["op", "filter", "on", "on_error", "endpoint"],
  "set-prompt-action": ["op", "category", "action"],
  "remove-prompt-action": ["op", "category"],
  "add-prompt-exception": ["op", "category", "match"],
  "remove-prompt-exception": ["op", "category", "match"],
};

export interface ApplyEditsOptions {
  /** Stamped on minted user rules as `by`. */
  by?: string;
  /** Clock for `added` on minted user rules. */
  now?: number;
}

export type ApplyEditsResult =
  | { ok: true; document: PolicyFileConfig }
  | { ok: false; problems: string[] };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.trim() !== "";
}

/** The identity of a `paths:` entry: a pattern by its text, a literal by its
 *  normalized path (so `~/x` and `/home/u/x` are the same label). */
export function pathIdentity(p: string): string {
  if (hasGlobMeta(p)) return `glob:${p.trim()}`;
  return normalizeLabelPath(p.replace(/\\([*?\[\]\\])/g, "$1")) ?? `raw:${p}`;
}

function nextRuleId(rules: readonly UserRuleEntry[]): string {
  const taken = new Set(rules.map((r) => r.id));
  let n = rules.length + 1;
  while (taken.has(`r-${String(n).padStart(4, "0")}`)) n++;
  return `r-${String(n).padStart(4, "0")}`;
}

function samePort(a: number | "*" | undefined, b: number | "*" | undefined): boolean {
  return (a ?? 443) === (b ?? 443);
}

/**
 * Apply `edits` to a copy of `document` (null = the built-ins, an empty
 * document) and validate the result. Pure; the input is never modified.
 */
export function applyEdits(document: PolicyFileConfig | null, edits: unknown, opts: ApplyEditsOptions = {}): ApplyEditsResult {
  if (!Array.isArray(edits) || edits.length === 0) return { ok: false, problems: ["edits: must be a non-empty list"] };
  const doc: PolicyFileConfig = document ? structuredClone(document) : {};
  const problems: string[] = [];
  edits.forEach((raw, i) => {
    const at = `edits[${i}]`;
    if (!isPlainObject(raw) || typeof raw.op !== "string") {
      problems.push(`${at}: must be a mapping with an 'op'`);
      return;
    }
    const allowed = (EDIT_KEYS as Record<string, readonly string[] | undefined>)[raw.op];
    const extra = allowed ? Object.keys(raw).filter((k) => !allowed.includes(k)) : [];
    if (extra.length > 0) {
      problems.push(`${at} (${raw.op}): unknown key${extra.length > 1 ? "s" : ""} ${extra.map((k) => `'${k}'`).join(", ")} (allowed: ${allowed!.slice(1).join(", ")})`);
      return;
    }
    const p = applyOne(doc, raw as PolicyEdit, opts);
    if (p) problems.push(`${at} (${raw.op}): ${p}`);
  });
  if (problems.length > 0) return { ok: false, problems };
  doc.version ??= 1;
  // Plan 12 D5: the edits may keep the conflicts with the administrator's
  // layer that `document` has; one they add is refused.
  const invalid = validatePolicyDocument(doc, getAdminLayer(), { tolerate: document });
  if (invalid.length > 0) return { ok: false, problems: invalid };
  return { ok: true, document: doc };
}

/** One edit onto `doc` in place (doc is already a private copy). Returns a
 *  problem, or null. */
function applyOne(doc: PolicyFileConfig, e: PolicyEdit, opts: ApplyEditsOptions): string | null {
  switch (e.op) {
    case "lock-path": {
      if (!nonEmpty(e.path)) return "path: must be a non-empty string";
      if (e.recursive !== undefined && typeof e.recursive !== "boolean") return "recursive: must be true or false";
      if (e.bindings !== undefined && (!Array.isArray(e.bindings) || !e.bindings.every(nonEmpty))) return "bindings: must be a list of hosts";
      const paths = (doc.paths ??= []);
      const id = pathIdentity(e.path);
      const idx = paths.findIndex((x) => pathIdentity(x.path) === id);
      // Replace level, bindings and recursive; keep the expert-only fields the
      // grammar cannot set (readers / others / extract / values). `values:`
      // (plan 13 §5.2) is kept at every level: under `public` it decides
      // nothing, and a later secret label finds it again.
      const kept: Partial<PathLabelEntry> = idx >= 0
        ? {
            ...(paths[idx]!.extract !== undefined ? { extract: paths[idx]!.extract } : {}),
            ...(paths[idx]!.values !== undefined ? { values: paths[idx]!.values } : {}),
            ...(paths[idx]!.readers !== undefined ? { readers: paths[idx]!.readers } : {}),
            ...(paths[idx]!.others !== undefined ? { others: paths[idx]!.others } : {}),
          }
        : {};
      const entry: PathLabelEntry = {
        path: idx >= 0 ? paths[idx]!.path : e.path,
        level: e.level,
        ...(e.bindings && e.bindings.length > 0 ? { bindings: [...e.bindings] } : {}),
        ...(e.recursive === false ? { recursive: false } : {}),
        ...kept,
      };
      if (idx >= 0) paths[idx] = entry;
      else paths.push(entry);
      return null;
    }
    case "unlock-path": {
      if (!nonEmpty(e.path)) return "path: must be a non-empty string";
      const id = pathIdentity(e.path);
      const before = doc.paths?.length ?? 0;
      doc.paths = (doc.paths ?? []).filter((x) => pathIdentity(x.path) !== id);
      if (doc.paths.length === before) return `no lock on ${e.path}`;
      if (doc.paths.length === 0) delete doc.paths;
      return null;
    }
    case "lock-blob": {
      // The id grammar, the level and the note are the validator's
      // (checkBlobs), judged on the whole result like a hand-written file.
      if (!nonEmpty(e.blob)) return "blob: must be an object id (sha1:<40 hex> or sha256:<64 hex>)";
      if (e.note !== undefined && typeof e.note !== "string") return "note: must be a string";
      const blobs = (doc.blobs ??= []);
      const idx = blobs.findIndex((b) => b.id === e.blob);
      // Replace the level; a note left out keeps the one already written.
      const note = e.note !== undefined ? e.note : idx >= 0 ? blobs[idx]!.note : undefined;
      const entry: BlobLockEntry = { id: e.blob, level: e.level, ...(note !== undefined && note !== "" ? { note } : {}) };
      if (idx >= 0) blobs[idx] = entry;
      else blobs.push(entry);
      return null;
    }
    case "unlock-blob": {
      if (!nonEmpty(e.blob)) return "blob: must be an object id (sha1:<40 hex> or sha256:<64 hex>)";
      const before = doc.blobs?.length ?? 0;
      doc.blobs = (doc.blobs ?? []).filter((b) => b.id !== e.blob);
      if (doc.blobs.length === before) return `no lock on ${e.blob}`;
      if (doc.blobs.length === 0) delete doc.blobs;
      return null;
    }
    case "trust-origin":
    case "distrust-origin": {
      if (e.kind !== "url" && e.kind !== "dir" && e.kind !== "channel") return "kind: must be url | dir | channel";
      if (!nonEmpty(e.pattern)) return "pattern: must be a non-empty string";
      // The URL category matches `host`, `*.suffix` or `host/path` with NO
      // scheme (trust-category.ts parseUrlPattern): `https://pypi.org/` would
      // parse as the host "https:" and never match. Models write the scheme,
      // so it is stripped here (with a lone trailing slash) rather than
      // stored as a rule that silently does nothing.
      const pattern = e.kind === "url"
        ? e.pattern.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^([^/]+)\/$/, "$1")
        : e.pattern;
      if (pattern === "") return "pattern: a URL pattern needs a host";
      // Only the list the category's EFFECTIVE mode reads is written
      // (allowlist ⇔ default UNTRUSTED reads trustedList; blocklist ⇔ TRUSTED
      // reads untrustedList; the validator refuses the other, dead, list).
      // So trusting under a TRUSTED default removes a block entry, and
      // distrusting under an UNTRUSTED default removes an allow entry; either
      // may be a no-op. A new section pins the default in the file, so the edit
      // means the same to any arbiter that reads it (an absent `default` meant
      // "trust everything" before 2026-09-25; policy-engine.ts).
      const inbound = (doc.inbound ??= {});
      const existing = inbound[e.kind];
      const def = existing?.default ?? BUILTIN_ORIGIN_DEFAULT[e.kind];
      const listKey = def === "UNTRUSTED" ? "trustedList" : "untrustedList";
      const shouldList = (e.op === "trust-origin") === (def === "UNTRUSTED");
      if (shouldList) {
        const cat = (inbound[e.kind] ??= { default: def });
        const list = (cat[listKey] ??= []);
        if (!list.includes(pattern)) list.push(pattern);
      } else if (existing?.[listKey]) {
        existing[listKey] = existing[listKey]!.filter((v) => v !== pattern);
        if (existing[listKey]!.length === 0) delete existing[listKey];
      }
      if (Object.keys(inbound).length === 0) delete doc.inbound;
      return null;
    }
    case "release": {
      if (!isPlainObject(e.to) || !nonEmpty(e.to.host)) return "to.host: must be a host, \"*\" or an @list reference";
      if (e.from !== undefined && (!isPlainObject(e.from) || !nonEmpty(e.from.host))) return "from.host: must be a host or an @list reference";
      if (e.mode !== "allow" && e.mode !== "block" && e.mode !== "audit") return "mode: must be allow | block | audit";
      for (const side of ["from", "to"] as const) {
        const extra = e[side] ? Object.keys(e[side]!).filter((k) => k !== "host") : [];
        if (extra.length > 0) return `${side}: only 'host' is allowed (got ${extra.map((k) => `'${k}'`).join(", ")})`;
      }
      if (e.expires !== undefined && e.expires !== null && typeof e.expires !== "string") return "expires: must be an ISO date/time or null";
      if (e.reason !== undefined && typeof e.reason !== "string") return "reason: must be a string";
      const rules = (doc.user_rules ??= []);
      const idx = e.id !== undefined ? rules.findIndex((r) => r.id === e.id) : -1;
      const prior = idx >= 0 ? rules[idx]! : undefined;
      const rule: UserRuleEntry = {
        id: e.id ?? nextRuleId(rules),
        kind: "release",
        ...(e.from ? { from: { host: e.from.host } } : {}),
        to: { host: e.to.host },
        mode: e.mode,
        ...(e.reason !== undefined ? { reason: e.reason } : prior?.reason !== undefined ? { reason: prior.reason } : {}),
        ...(opts.by !== undefined ? { by: opts.by } : prior?.by !== undefined ? { by: prior.by } : {}),
        added: prior?.added ?? new Date(opts.now ?? Date.now()).toISOString(),
        ...(e.expires !== undefined && e.expires !== null ? { expires: e.expires } : {}),
      };
      if (idx >= 0) rules[idx] = rule;
      else rules.push(rule);
      return null;
    }
    case "retire-rule": {
      const before = doc.user_rules?.length ?? 0;
      doc.user_rules = (doc.user_rules ?? []).filter((r) => r.id !== e.id);
      if (doc.user_rules.length === before) return `no user rule with id ${JSON.stringify(e.id)}`;
      if (doc.user_rules.length === 0) delete doc.user_rules;
      return null;
    }
    case "set-disposition": {
      if (!nonEmpty(e.rule)) return "rule: must be a built-in rule id";
      if (e.mode !== "ask" && e.mode !== "block") return "mode: must be ask | block";
      (doc.rules ??= {})[e.rule] = { mode: e.mode };
      return null;
    }
    case "allow-connect": {
      if (!nonEmpty(e.host)) return "host: must be a host or an @list reference";
      const dests = (doc.destinations ??= []);
      if (!dests.some((d) => d.host === e.host && samePort(d.port, e.port) && d.connect === "allow")) {
        dests.push({ host: e.host, ...(e.port !== undefined ? { port: e.port } : {}), connect: "allow" });
      }
      return null;
    }
    case "remove-connect": {
      if (!nonEmpty(e.host)) return "host: must be a host or an @list reference";
      const before = doc.destinations?.length ?? 0;
      doc.destinations = (doc.destinations ?? []).filter((d) => !(d.host === e.host && samePort(d.port, e.port)));
      if (doc.destinations.length === before) return `no destination rule for ${e.host}${e.port !== undefined ? `:${e.port}` : ""}`;
      if (doc.destinations.length === 0) delete doc.destinations;
      return null;
    }
    case "trust-command": {
      if (!nonEmpty(e.id)) return "id: must be a command id";
      if (typeof e.trustHelp !== "boolean") return "trustHelp: must be true or false";
      const commands = ((doc.inbound ??= {}).command ??= []);
      const entry = commands.find((c) => c.id === e.id);
      if (entry) entry.trustHelp = e.trustHelp;
      else commands.push({ id: e.id, trustHelp: e.trustHelp });
      return null;
    }
    case "tool-inbound": {
      if (!nonEmpty(e.tool)) return "tool: must be a tool name";
      if (e.trust !== "TRUSTED" && e.trust !== "UNTRUSTED") return "trust: must be TRUSTED | UNTRUSTED";
      const tools = (doc.tools ??= {});
      tools[e.tool] = { ...(tools[e.tool] ?? {}), inbound: e.trust };
      return null;
    }
    case "list": {
      if (!nonEmpty(e.name)) return "name: must be a list name";
      for (const k of ["add", "remove"] as const) {
        if (e[k] !== undefined && (!Array.isArray(e[k]) || !e[k]!.every(nonEmpty))) return `${k}: must be a list of non-empty strings`;
      }
      const lists = (doc.lists ??= {});
      if (!lists[e.name] && e.remove?.length) return `no list named ${e.name}`;
      const members = [...(lists[e.name] ?? [])];
      for (const v of e.add ?? []) if (!members.includes(v)) members.push(v);
      const drop = new Set(e.remove ?? []);
      lists[e.name] = members.filter((v) => !drop.has(v));
      return null;
    }
    case "add-model":
    case "update-model": {
      // Shape and content (name grammar, http(s) url with no credentials,
      // wire, the cloud-model rule for local: true, token_env a variable
      // NAME) are checked by validatePolicyDocument's checkModels on the
      // whole result, the same rules a hand-written file meets.
      if (!nonEmpty(e.name)) return "name: must be a non-empty string";
      const models = (doc.models ??= []);
      const idx = models.findIndex((m) => m.name === e.name);
      // Plan 12 D5: an administrator's entry is changed by an entry of the
      // same name here (the lock, if any, is judged on the result).
      const admin = getAdminLayer().models.find((m) => m.entry.name === e.name);
      if (e.op === "add-model" && idx >= 0 && models[idx]!.disabled !== true) return `a model named ${JSON.stringify(e.name)} is already declared (change it with update-model)`;
      if (e.op === "add-model" && admin && idx < 0) return `a model named ${JSON.stringify(e.name)} is set by your administrator (${admin.file}); change it with update-model`;
      if (e.op === "update-model" && idx < 0 && !admin) return `no model named ${JSON.stringify(e.name)}`;
      // update-model replaces the entry whole: a field left out is removed,
      // as lock-path replaces a label's level and bindings.
      const entry = {} as ModelEndpointEntry;
      for (const k of MODEL_FIELDS) if (e[k] !== undefined) (entry as unknown as Record<string, unknown>)[k] = e[k];
      if (idx >= 0) models[idx] = entry;
      else models.push(entry);
      return null;
    }
    case "remove-model": {
      if (!nonEmpty(e.name)) return "name: must be a non-empty string";
      // Plan 12 D5: an administrator's entry is removed by a marker in the
      // user's file (the administrator's file is read-only), which the lock
      // allows: removing a model only narrows where files may go.
      if (getAdminLayer().models.some((m) => m.entry.name === e.name)) {
        const models = (doc.models ??= []);
        const idx = models.findIndex((m) => m.name === e.name);
        if (idx >= 0 && models[idx]!.disabled === true) return `the model ${JSON.stringify(e.name)} is already removed`;
        const marker = { name: e.name, disabled: true } as ModelEndpointEntry;
        if (idx >= 0) models[idx] = marker;
        else models.push(marker);
        return null;
      }
      const before = doc.models?.length ?? 0;
      doc.models = (doc.models ?? []).filter((m) => m.name !== e.name);
      if (doc.models.length === before) return `no model named ${JSON.stringify(e.name)}`;
      if (doc.models.length === 0) delete doc.models;
      return null;
    }
    case "restore-model": {
      // Plan 12 D5: bring back an administrator's entry the user removed,
      // by dropping the user's `{ name, disabled: true }` marker.
      if (!nonEmpty(e.name)) return "name: must be a non-empty string";
      if (!getAdminLayer().models.some((m) => m.entry.name === e.name)) return `no model named ${JSON.stringify(e.name)} is set by your administrator`;
      const idx = (doc.models ?? []).findIndex((m) => m.name === e.name && m.disabled === true);
      if (idx < 0) return `the model ${JSON.stringify(e.name)} is not removed`;
      doc.models!.splice(idx, 1);
      if (doc.models!.length === 0) delete doc.models;
      return null;
    }
    case "map-sensitivity-label": {
      // Plan 14 §14.1. The GUIDs, the name and the level are the
      // validator's (checkSensitivityLabels) on the whole result; here only
      // the entry's identity: (id, site), compared lowercase without braces.
      if (!nonEmpty(e.id)) return "id: must be a label GUID";
      if (e.site !== undefined && !nonEmpty(e.site)) return "site: must be a tenant GUID (or left out)";
      const labels = (doc.sensitivity_labels ??= []);
      const key = labelKey(e.id, e.site);
      const idx = labels.findIndex((l) => labelKey(l.id, l.site) === key);
      const entry: SensitivityLabelEntry = { id: e.id, ...(e.site !== undefined ? { site: e.site } : {}), name: e.name, level: e.level };
      if (idx >= 0) labels[idx] = entry;
      else labels.push(entry);
      return null;
    }
    case "unmap-sensitivity-label": {
      if (!nonEmpty(e.id)) return "id: must be a label GUID";
      const key = labelKey(e.id, e.site);
      const before = doc.sensitivity_labels?.length ?? 0;
      doc.sensitivity_labels = (doc.sensitivity_labels ?? []).filter((l) => labelKey(l.id, l.site) !== key);
      if (doc.sensitivity_labels.length === before) return `no mapping for the label ${e.id}${e.site ? ` (site ${e.site})` : ""}`;
      if (doc.sensitivity_labels.length === 0) delete doc.sensitivity_labels;
      return null;
    }
    case "set-prompt-filter": {
      // Grammar and content (ids, on_error, the lock) are the validator's
      // (checkPromptFilters, promptLockProblems) on the whole result.
      if (!nonEmpty(e.filter)) return "filter: must be a filter or pack id";
      if (typeof e.on !== "boolean") return "on: must be true or false";
      if (e.on_error !== undefined && e.on_error !== null && e.on_error !== "block" && e.on_error !== "pass") return "on_error: must be block, pass or null";
      // Plan 15 phase 3: a classifier plugin's model (a relaxation whichever
      // way it moves, comparePromptFilters); null removes it.
      if (e.endpoint !== undefined && e.endpoint !== null && !nonEmpty(e.endpoint)) return "endpoint: must be a model's name or null";
      const pf = promptFilters(doc);
      const filters = (pf.filters ??= {});
      const prev = filters[e.filter];
      const prevOnError = prev !== null && typeof prev === "object" ? prev.on_error : undefined;
      const prevEndpoint = prev !== null && typeof prev === "object" ? prev.endpoint : undefined;
      const onError = e.on_error === undefined ? prevOnError : e.on_error ?? undefined;
      const endpoint = e.endpoint === undefined ? prevEndpoint : e.endpoint ?? undefined;
      filters[e.filter] = onError === undefined && endpoint === undefined
        ? (e.on ? "on" : "off")
        : { on: e.on, ...(onError !== undefined ? { on_error: onError } : {}), ...(endpoint !== undefined ? { endpoint } : {}) };
      return null;
    }
    case "set-prompt-action": {
      if (!nonEmpty(e.category)) return "category: must be a dotted category such as pii.email";
      (promptFilters(doc).actions ??= {})[e.category] = e.action;
      return null;
    }
    case "remove-prompt-action": {
      if (!nonEmpty(e.category)) return "category: must be a dotted category such as pii.email";
      const actions = doc.prompt_filters?.actions;
      if (!actions || !(e.category in actions)) return `no action row for ${e.category}`;
      delete actions[e.category];
      prunePromptFilters(doc);
      return null;
    }
    case "add-prompt-exception": {
      if (!nonEmpty(e.category) || typeof e.match !== "string") return "category and match: required";
      const list = (promptFilters(doc).exceptions ??= []);
      if (!list.some((x) => x.category === e.category && x.match === e.match)) list.push({ category: e.category, match: e.match });
      return null;
    }
    case "remove-prompt-exception": {
      const list = doc.prompt_filters?.exceptions ?? [];
      const i = list.findIndex((x) => x.category === e.category && x.match === e.match);
      if (i < 0) return `no exception for ${String(e.category)} matching ${String(e.match)}`;
      list.splice(i, 1);
      prunePromptFilters(doc);
      return null;
    }
    default:
      return `unknown op (known: ${POLICY_EDIT_OPS.join(", ")})`;
  }
}

/** The document's `prompt_filters:` mapping, created when absent. */
function promptFilters(doc: PolicyFileConfig): PromptFiltersConfig {
  return (doc.prompt_filters ??= {});
}

/** Drop the empty parts of `prompt_filters:` an edit left behind. */
function prunePromptFilters(doc: PolicyFileConfig): void {
  const pf = doc.prompt_filters;
  if (!pf) return;
  if (pf.filters && Object.keys(pf.filters).length === 0) delete pf.filters;
  if (pf.actions && Object.keys(pf.actions).length === 0) delete pf.actions;
  if (pf.exceptions && pf.exceptions.length === 0) delete pf.exceptions;
  if (Object.keys(pf).length === 0) delete doc.prompt_filters;
}

/** A `sensitivity_labels:` entry's identity: (id, site), lowercase, no braces
 *  (`id|site`, site empty when absent): the item key of its mapping. */
export function labelKey(id: string, site: string | undefined): string {
  const g = (v: string): string => {
    const s = v.trim().toLowerCase();
    return s.startsWith("{") && s.endsWith("}") ? s.slice(1, -1) : s;
  };
  return `${g(id)}|${site === undefined ? "" : g(site)}`;
}

export type EditEvaluation =
  | { ok: false; problems: string[] }
  | { ok: true; document: PolicyFileConfig; delta: PolicyDelta; tightening: boolean; after: CompiledPolicy };

/**
 * The pure core of `policyPropose` (§4.2): apply the edits to the document in
 * force, compile both laws under the same boot spec, and classify the change.
 * `tightening` true ⇒ the data plane may apply `document`; false ⇒ it is a
 * proposal and `delta.relaxations` is what the human would be giving up.
 */
export function evaluateEdits(
  before: { specId: InboundSpecId; document: PolicyFileConfig | null },
  edits: unknown,
  opts: ApplyEditsOptions = {},
): EditEvaluation {
  const r = applyEdits(before.document, edits, opts);
  if (!r.ok) return r;
  const b = compilePolicy({ specId: before.specId, document: before.document });
  const a = compilePolicy({ specId: before.specId, document: r.document });
  const delta = policyDelta(b, a, { now: opts.now });
  return { ok: true, document: r.document, delta, tightening: isTightening(delta), after: a };
}

// ── undo: item-level revert (§4.2 `undoPolicyChange`) ────────────────────────
//
// Undo does NOT restore the old file: later changes to OTHER items must
// survive. A change is recorded as the list of ITEMS it touched (a lock by
// path, a user rule by id, a list by name, one origin pattern's membership,
// ...) with each item's value BEFORE the change; undo writes those values back
// onto the law in force and validates the result like any other document.

export type RevertSection =
  | "paths" | "blobs" | "user_rules" | "destinations" | "rules" | "lists" | "tools" | "command" | "apps" | "models"
  | "sensitivity-labels"
  | "origin" | "origin-default" | "env-secret" | "env-exempt" | "legacy"
  // Fail closed: a top-level key (or an `env:` sub-key) this module does not
  // model item by item reverts as ONE whole value, so a change under a key
  // added later (protect:, ssh_agent:, env.sources, ...) is never silently
  // left out of an Undo.
  | "key" | "env-key";

export interface RevertItem {
  section: RevertSection;
  key: string;
  /** The item's value before the change; null = it did not exist. */
  before: unknown;
  /** Its value right after the change (null = removed): Undo refuses when
   *  the item has changed again since, rather than overwrite that later edit. */
  after: unknown;
}

/** JSON with object keys sorted — a stable identity for hashing and comparing. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v as object).sort().filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

const destKey = (d: { host: string; port?: number | "*"; proto?: string }): string => `${d.host}|${d.port ?? 443}|${d.proto ?? "tcp"}`;
const ORIGIN_CATS = ["url", "channel", "dir"] as const;
const LEGACY_KEYS = ["channel-trust", "url-trust", "dir-trust"] as const;
/** Top-level keys itemized above; every other key is one whole-value item. */
const ITEMIZED_KEYS = new Set(["version", "paths", "blobs", "user_rules", "destinations", "rules", "lists", "tools", "apps", "inbound", "env", "models", "sensitivity_labels"]);

/** Every item of a document, keyed `section\0key` → value. */
function itemsOf(doc: PolicyFileConfig | null): Map<string, { section: RevertSection; key: string; value: unknown }> {
  const out = new Map<string, { section: RevertSection; key: string; value: unknown }>();
  const put = (section: RevertSection, key: string, value: unknown): void => { out.set(`${section}\0${key}`, { section, key, value }); };
  if (!doc) return out;
  for (const p of doc.paths ?? []) put("paths", pathIdentity(p.path), p);
  // One item per blob lock, by id (plan 14 §8.2): undoing one keeps a later
  // lock on another.
  for (const b of doc.blobs ?? []) put("blobs", b.id, b);
  for (const r of doc.user_rules ?? []) put("user_rules", r.id, r);
  for (const d of doc.destinations ?? []) put("destinations", destKey(d), d);
  for (const [id, d] of Object.entries(doc.rules ?? {})) put("rules", id, d);
  for (const [name, l] of Object.entries(doc.lists ?? {})) put("lists", name, l);
  for (const [name, t] of Object.entries(doc.tools ?? {})) put("tools", name, t);
  for (const c of doc.inbound?.command ?? []) put("command", c.id, c);
  for (const a of doc.apps ?? []) put("apps", a.app, a);
  // One item per declared model, by name (the name is what a session's
  // binding and inspect-mcp's routing refer to).
  for (const m of doc.models ?? []) put("models", m.name, m);
  // One item per sensitivity-label mapping, by its identity (id, site)
  // (policy-surface.md §8.4.6 "An item-level version": Settings › Sensitivity
  // labels names the mapping it read; until 2026-10-18 the section was one
  // whole-key item, and a change recorded then still reverts whole).
  for (const l of doc.sensitivity_labels ?? []) put("sensitivity-labels", labelKey(l.id, l.site), l);
  for (const cat of ORIGIN_CATS) {
    const c = doc.inbound?.[cat];
    if (!c) continue;
    if (c.default !== undefined) put("origin-default", cat, c.default);
    const members = new Set([...(c.trustedList ?? []), ...(c.untrustedList ?? [])]);
    for (const m of members) {
      put("origin", `${cat}\0${m}`, { trusted: (c.trustedList ?? []).includes(m), untrusted: (c.untrustedList ?? []).includes(m) });
    }
  }
  for (const n of doc.env?.secrets ?? []) put("env-secret", n, true);
  for (const n of doc.env?.exempt ?? []) put("env-exempt", n, true);
  for (const k of LEGACY_KEYS) if (doc.inbound?.[k] !== undefined) put("legacy", k, doc.inbound[k]);
  for (const [k, v] of Object.entries(doc)) if (!ITEMIZED_KEYS.has(k) && v !== undefined) put("key", k, v);
  for (const [k, v] of Object.entries(doc.env ?? {})) if (k !== "secrets" && k !== "exempt" && v !== undefined) put("env-key", k, v);
  return out;
}

/** One item's value in `doc` (null = absent), by the identity `diffItems`
 *  and Undo use: a model by name, a user rule by id, a lock by path, ...
 *  (policy-surface.md §8.4.6 "An item-level version"). */
export function itemValue(doc: PolicyFileConfig | null, section: string, key: string): unknown {
  return currentValue(doc, itemsOf(doc), { section: section as RevertSection, key, before: null, after: null });
}

/** Every item of `doc` as `section → key → value` (the identity of
 *  {@link itemValue}). */
export function itemValues(doc: PolicyFileConfig | null): Map<string, Map<string, unknown>> {
  const out = new Map<string, Map<string, unknown>>();
  for (const it of itemsOf(doc).values()) {
    let m = out.get(it.section);
    if (!m) out.set(it.section, (m = new Map()));
    m.set(it.key, it.value);
  }
  return out;
}

/** The items `after` changed relative to `before`, with their before values. */
export function diffItems(before: PolicyFileConfig | null, after: PolicyFileConfig | null): RevertItem[] {
  const b = itemsOf(before);
  const a = itemsOf(after);
  const out: RevertItem[] = [];
  for (const id of new Set([...b.keys(), ...a.keys()])) {
    const bi = b.get(id);
    const ai = a.get(id);
    if (bi && ai && canonicalJson(bi.value) === canonicalJson(ai.value)) continue;
    const it = (bi ?? ai)!;
    out.push({ section: it.section, key: it.key, before: bi ? structuredClone(bi.value) : null, after: ai ? structuredClone(ai.value) : null });
  }
  return out;
}

/** The items whose value in `doc` is no longer what the change left there
 *  (`section key` each). Non-empty ⇒ Undo would overwrite a later edit. */
export function revertConflicts(doc: PolicyFileConfig | null, items: readonly RevertItem[]): string[] {
  const now = itemsOf(doc);
  const out: string[] = [];
  for (const it of items) {
    const cur = currentValue(doc, now, it);
    if (canonicalJson(cur) !== canonicalJson(it.after ?? null)) out.push(`${it.section} ${it.key.replace("\0", " ")}`);
  }
  return out;
}

/** Each item of a change as it stands now: `current` = its value in `doc` is
 *  still what the change left there (no later edit, recorded or by hand). */
export function itemStates(doc: PolicyFileConfig | null, items: readonly RevertItem[]): Array<RevertItem & { current: boolean }> {
  const now = itemsOf(doc);
  return items.map((it) => ({ ...it, current: canonicalJson(currentValue(doc, now, it)) === canonicalJson(it.after ?? null) }));
}

/** An item's value in `doc` now. A whole-key item (section `key`) is read
 *  from the document itself, so a change recorded before its key was
 *  itemized (`models:` until 2026-09-28) still compares and reverts. */
function currentValue(doc: PolicyFileConfig | null, now: ReturnType<typeof itemsOf>, it: RevertItem): unknown {
  if (it.section === "key") return (doc as Record<string, unknown> | null)?.[it.key] ?? null;
  return now.get(`${it.section}\0${it.key}`)?.value ?? null;
}

/** Write each item's before value onto a copy of `doc` and validate. */
export function revertItems(doc: PolicyFileConfig | null, items: readonly RevertItem[]): ApplyEditsResult {
  const out: PolicyFileConfig = doc ? structuredClone(doc) : {};
  const upsert = <T>(list: T[] | undefined, match: (x: T) => boolean, value: T | null): T[] => {
    const l = [...(list ?? [])];
    const i = l.findIndex(match);
    if (value === null) { if (i >= 0) l.splice(i, 1); }
    else if (i >= 0) l[i] = value;
    else l.push(value);
    return l;
  };
  const setMap = <T>(m: Record<string, T> | undefined, key: string, value: T | null): Record<string, T> => {
    const r = { ...(m ?? {}) };
    if (value === null) delete r[key];
    else r[key] = value;
    return r;
  };
  const setMember = (list: string[] | undefined, name: string, on: boolean): string[] => {
    const l = (list ?? []).filter((x) => x !== name);
    if (on) l.push(name);
    return l;
  };
  for (const it of items) {
    const v = it.before as never;
    switch (it.section) {
      case "paths": out.paths = upsert(out.paths, (p) => pathIdentity(p.path) === it.key, v); break;
      case "blobs": out.blobs = upsert(out.blobs, (b) => b.id === it.key, v); break;
      case "user_rules": out.user_rules = upsert(out.user_rules, (r) => r.id === it.key, v); break;
      case "destinations": out.destinations = upsert(out.destinations, (d) => destKey(d) === it.key, v); break;
      case "rules": out.rules = setMap(out.rules, it.key, v); break;
      case "lists": out.lists = setMap(out.lists, it.key, v); break;
      case "tools": out.tools = setMap(out.tools, it.key, v); break;
      case "apps": out.apps = upsert(out.apps, (a) => a.app === it.key, v); break;
      case "models": out.models = upsert(out.models, (m) => m.name === it.key, v); break;
      case "sensitivity-labels": out.sensitivity_labels = upsert(out.sensitivity_labels, (l) => labelKey(l.id, l.site) === it.key, v); break;
      case "command": {
        const inbound = (out.inbound ??= {});
        inbound.command = upsert(inbound.command, (c) => c.id === it.key, v);
        break;
      }
      case "origin": {
        const [cat, pattern] = it.key.split("\0") as [(typeof ORIGIN_CATS)[number], string];
        const c = ((out.inbound ??= {})[cat] ??= {});
        const m = (it.before ?? { trusted: false, untrusted: false }) as { trusted: boolean; untrusted: boolean };
        c.trustedList = setMember(c.trustedList, pattern, m.trusted);
        c.untrustedList = setMember(c.untrustedList, pattern, m.untrusted);
        break;
      }
      case "origin-default": {
        const c = ((out.inbound ??= {})[it.key as (typeof ORIGIN_CATS)[number]] ??= {});
        if (it.before === null) delete c.default;
        else c.default = it.before as "TRUSTED" | "UNTRUSTED";
        break;
      }
      case "env-secret": out.env = { ...(out.env ?? {}), secrets: setMember(out.env?.secrets, it.key, it.before !== null) }; break;
      case "env-exempt": out.env = { ...(out.env ?? {}), exempt: setMember(out.env?.exempt, it.key, it.before !== null) }; break;
      case "key": {
        const d = out as Record<string, unknown>;
        if (it.before === null) delete d[it.key];
        else d[it.key] = it.before;
        break;
      }
      case "env-key": {
        const env = { ...(out.env ?? {}) } as Record<string, unknown>;
        if (it.before === null) delete env[it.key];
        else env[it.key] = it.before;
        out.env = env as PolicyFileConfig["env"];
        break;
      }
      case "legacy": {
        const inbound = (out.inbound ??= {}) as Record<string, unknown>;
        if (it.before === null) delete inbound[it.key];
        else inbound[it.key] = it.before;
        break;
      }
    }
  }
  pruneEmpty(out);
  const invalid = validatePolicyDocument(out, getAdminLayer(), { tolerate: doc });
  if (invalid.length > 0) return { ok: false, problems: invalid };
  return { ok: true, document: out };
}

/** What {@link layerItems} answers: the other document with the change, or
 *  why the change cannot be made to it as well. */
export type LayerItemsResult =
  | { ok: true; document: PolicyFileConfig }
  | { ok: false; conflicts: string[]; problems: string[] };

/**
 * The change `before → after` made to another document `doc`, item by item
 * (policy-surface.md §8.4.6: a write while a hand edit of policy.yaml waits
 * in Approvals is made to the held edit as well). Each item the change
 * touched (a lock by path, a user rule by id, a list by name, …;
 * {@link diffItems}) is set in `doc` to its value in `after`, and every
 * other item of `doc` is kept as it is. The Undo's own mechanism run
 * forwards: `revertItems` with each item's after value.
 *
 * Refused (`conflicts`, `section key` each) when `doc` holds another value
 * than `before` did for one of those items: `doc` changed the same item, and
 * writing the change over it would drop that edit. Refused (`problems`) when
 * the result does not validate. Pure.
 */
export function layerItems(doc: PolicyFileConfig | null, before: PolicyFileConfig | null, after: PolicyFileConfig | null): LayerItemsResult {
  const forward = diffItems(before, after).map((it) => ({ ...it, before: it.after, after: it.before }));
  const conflicts = revertConflicts(doc, forward);
  if (conflicts.length > 0) return { ok: false, conflicts, problems: [] };
  if (forward.length === 0) return { ok: true, document: doc ? structuredClone(doc) : {} };
  const r = revertItems(doc, forward);
  return r.ok ? r : { ok: false, conflicts: [], problems: r.problems };
}

/** Drop sections a revert emptied, so an undo does not leave `paths: []` noise. */
function pruneEmpty(doc: PolicyFileConfig): void {
  const d = doc as Record<string, unknown>;
  for (const k of ["paths", "blobs", "user_rules", "destinations", "apps", "models", "sensitivity_labels"]) if (Array.isArray(d[k]) && (d[k] as unknown[]).length === 0) delete d[k];
  for (const k of ["rules", "lists", "tools"]) if (d[k] && Object.keys(d[k] as object).length === 0) delete d[k];
  if (doc.env) {
    if (doc.env.secrets?.length === 0) delete doc.env.secrets;
    if (doc.env.exempt?.length === 0) delete doc.env.exempt;
    if (Object.keys(doc.env).length === 0) delete doc.env;
  }
  if (doc.inbound) {
    for (const cat of ORIGIN_CATS) {
      const c = doc.inbound[cat];
      if (!c) continue;
      if (c.trustedList?.length === 0) delete c.trustedList;
      if (c.untrustedList?.length === 0) delete c.untrustedList;
      if (Object.keys(c).length === 0) delete doc.inbound[cat];
    }
    if (doc.inbound.command?.length === 0) delete doc.inbound.command;
    if (Object.keys(doc.inbound).length === 0) delete doc.inbound;
  }
}
