/**
 * compiled-policy — compile, don't mutate (docs/design/ui/policy-surface.md
 * §2.2, stage 3).
 *
 * BEFORE: the active inbound spec table, the outbound resolve/field maps and
 * the exec-output trust index were MODULE GLOBALS that `tool-overrides.ts` and
 * `exec-inbound.ts` edited IN PLACE when a policy file loaded, with a `let`
 * spec id selected by `setActiveInboundSpec`. Nothing could be reloaded
 * safely, tests isolated only because node runs each file in its own process,
 * and a YAML override permanently rewrote the built-in constants for the rest
 * of the process.
 *
 * NOW: `compilePolicy(input)` is a PURE function from (spec id, policy
 * document) to an immutable {@link CompiledPolicy} — the built-in tables are
 * copied, the overrides are applied to the copies, and the result is frozen.
 * One process-wide `current` pointer holds the law in force; swapping it is
 * atomic and the built-in constants are never touched. The accessors the rest
 * of the engine already uses (`getActiveInboundSpec`, `destinationKind`,
 * `classifyExecOutput`, the snapshot) read through `current`, so no call site
 * changed shape. Session→spec bindings stay where they were: they are runtime
 * STATE about sessions, not law.
 *
 * `relaxationsOf(compiled)` lists every place the compiled law is more
 * permissive than the built-ins — the data behind the dashboard's Relaxations
 * list (§2.4) and the invariant that the built-ins relax nothing.
 */
import { compileModelTls, type ModelTls } from "./model-tls.js";
import { compilePerimeter, domainMatches, perimeterApplies, urlHost, type Perimeter } from "./model-perimeter.js";
import { endpointPlacement } from "./model-placement.js";
import { effectiveModels, getAdminLayer, hasAdminLayer, type AdminLayer, type EffectiveModelEntry } from "./admin-layer.js";
import type { AppEntry, BlobLockEntry, DestinationEntry, EnvSecretsEntry, ModelEndpointEntry, PathLabelEntry, PolicyFileConfig, UserRuleEntry } from "./load-policy.js";
import { appRuleRefusal, readerOutputRefusal, type AppRule } from "./flow-taint.js";
import type { PolicyLawSource } from "./load-policy.js";
import { compilePathGlob, hasGlobMeta } from "./path-glob.js";
import { normalizeLabelPath, type PathLabel } from "./path-labels.js";
import { compileValueRules } from "./value-bindings.js";
import { confidentialityRank, isConfidentialityLevel, type ConfidentialityLevel, type ModelLocation } from "../symbol-table/confidentiality.js";
import type { SchemaNode, ToolSpec } from "./schema-types.js";
import { isActionSpec } from "./schema-types.js";
import {
  BUILTIN_INBOUND_SPECS,
  INBOUND_SPEC_IDS,
  type InboundSpecId,
} from "./tool-inbound.js";
import {
  BUILTIN_OUTBOUND_FIELD_POLICY,
  BUILTIN_OUTBOUND_RESOLVE,
  type InputFieldPolicy,
} from "./tool-outbound.js";
import { applyToolOverrides } from "./tool-overrides.js";
import { compileMappedTools } from "./mapped-tools.js";
import { compileIssuerBindings, type IssuerBindingSettings } from "./issuer-bindings.js";
import {
  applyCommandOverrides,
  BUILTIN_EXEC_RESULT_TRUST_ENTRIES,
  type ExecOutputSpec,
} from "./exec-inbound.js";

export interface CompileLogger {
  info(msg: string): void;
  warn(msg: string): void;
}

const SILENT: CompileLogger = { info: () => {}, warn: () => {} };

/** A user rule with its `@list` references expanded (policy-surface.md §2.5). */
export interface CompiledUserRule {
  readonly id: string;
  readonly kind: "release";
  /** Origin hosts (lower-cased); null = any origin. */
  readonly from: readonly string[] | null;
  /** Destination hosts (lower-cased); ["*"] = any destination. */
  readonly to: readonly string[];
  readonly mode: "allow" | "block" | "audit" | "off";
  readonly reason?: string;
  readonly by?: string;
  readonly added?: string;
  /** Epoch millis after which the rule is ignored; null = never. */
  readonly expiresAt: number | null;
}

export interface CompiledPolicy {
  /** The process-global boot spec (a session may be bound to another id; the
   *  tables below exist for every id, overrides applied to THIS one). */
  readonly specId: InboundSpecId;
  readonly inbound: Readonly<Record<InboundSpecId, Readonly<Record<string, ToolSpec>>>>;
  readonly outboundResolve: Readonly<Record<InboundSpecId, Readonly<Record<string, boolean>>>>;
  readonly outboundFieldPolicy: Readonly<Record<InboundSpecId, Readonly<Record<string, Readonly<Record<string, InputFieldPolicy>>>>>>;
  /** Exec-output trust index: built-in entries + the document's command overrides (aliases indexed). */
  readonly execIndex: Readonly<Record<string, ExecOutputSpec>>;
  /** Named lists, as declared. */
  readonly lists: Readonly<Record<string, readonly string[]>>;
  /** Locked-file labels declared in the document (source "policy-file"),
   *  keyed by normalized path — composed with the DB labels by the server. */
  readonly pathLabels: ReadonlyMap<string, PathLabel>;
  /** Plan 14 §8.2: policy.yaml `blobs:`, keyed by id (`sha1:…` / `sha256:…`).
   *  The launcher's object twins hide every one above `public`. */
  readonly blobLocks: ReadonlyMap<string, BlobLock>;
  /** Operator dispositions on built-in ask rules (rule id → mode). */
  readonly dispositions: Readonly<Record<string, "ask" | "block">>;
  /** User rules with lists expanded, in document order. */
  readonly userRules: readonly CompiledUserRule[];
  /** Reachability rules (§2.3, stage 4b) with lists expanded — one per host. */
  readonly destinations: readonly CompiledDestination[];
  /** Plan 10 §2.2: per-app output rules, keyed by program name. DEPRECATED
   *  (Plan 13 D3): no fold reads it; kept for policyDelta and the dashboard. */
  readonly apps: ReadonlyMap<string, AppRule>;
  /** Plan 10 §11.4: the law's additions to / exemptions from the env-var mask
   *  (names or `PREFIX_*` patterns). Empty lists when the document has none. */
  readonly envSecrets: EnvSecretRules;
  /** `env.sources`: variables a launch fills from a keystore or a command. */
  readonly envSources: readonly CompiledEnvSource[];
  /** policy.yaml `ssh_agent.readers`, or null (the agent socket is ungated). */
  readonly sshAgentReaders: readonly unknown[] | null;
  /** policy.yaml `protect:` as written (the launcher expands `~`). */
  readonly protect: readonly string[];
  /** Plan 10 §11.18: policy.yaml `mapped_tools:`, the well-formed entries
   *  (mapped-tools.ts). Empty when the document has none. */
  readonly mappedTools: readonly string[];
  /** confidentiality.md §2.3: policy.yaml `issuer_bindings:` compiled
   *  (issuer-bindings.ts); the default (on) when the document has none. */
  readonly issuerBindings: IssuerBindingSettings;
  /** Plan 11 D2: declared model endpoints, defaults applied (wire
   *  `anthropic`, local false). Empty when the document declares none. */
  readonly models: readonly ModelEndpoint[];
  /** Plan 12 D4: policy.yaml `perimeter:`, or null. Already compiled onto
   *  each endpoint it applies to (`ModelEndpoint.perimeter`, `orgDomain`). */
  readonly perimeter: Perimeter | null;
  /** Plan 12 D5: the administrator's layer this law merged, or null. */
  readonly admin: { readonly dir: string | null; readonly files: readonly string[]; readonly locked: boolean; readonly perimeterFile: string | null } | null;
  /** The document this law was compiled from, as written (null = built-ins
   *  only). `@list` references stay as written here; see `lists`. */
  readonly document: PolicyFileConfig | null;
  readonly lawSource: PolicyLawSource;
}

/** One `blobs:` entry, compiled (plan 14 §8.2). */
export interface BlobLock {
  readonly id: string;
  readonly level: ConfidentialityLevel;
  readonly note?: string;
}

/** policy.yaml `blobs:` by id. A level the validator would refuse locks at
 *  the strictest level (a loader that skipped the validator must not turn a
 *  lock into nothing), as `paths:` does; an id that is not one is skipped
 *  (it names no object, so it can hide none). */
function compileBlobLocks(entries: readonly BlobLockEntry[] | undefined): ReadonlyMap<string, BlobLock> {
  const out = new Map<string, BlobLock>();
  for (const e of entries ?? []) {
    if (typeof e?.id !== "string" || !/^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/.test(e.id)) continue;
    const level = isConfidentialityLevel(e.level) ? e.level : "no-model";
    const prev = out.get(e.id);
    // Listed twice (refused by the validator): the stricter entry stands.
    if (prev && confidentialityRank(prev.level) >= confidentialityRank(level)) continue;
    out.set(e.id, Object.freeze({ id: e.id, level, ...(typeof e.note === "string" && e.note !== "" ? { note: e.note } : {}) }));
  }
  return out;
}

/** One declared model endpoint, defaults applied (plan 11 D2). The wire
 *  shape of the `modelEndpoints` op. */
export interface ModelEndpoint {
  readonly name: string;
  readonly url: string;
  readonly wire: "anthropic" | "openai-chat";
  readonly model?: string;
  readonly local: boolean;
  readonly tokenEnv?: string;
  /** `helper: true`: the quarantined helper's model (present only when true). */
  readonly helper?: true;
  /** `allow_plain_http: true` (plan 12 D2): the helper may reach this
   *  entry over plain http on another machine. Present only when true. */
  readonly allowPlainHttp?: true;
  /** `tls:` (plan 12 D3): absolute paths and pins, only when given. */
  readonly tls?: ModelTls;
  /** Plan 12 D4: `perimeter.networks`, on a `local: true` entry on another
   *  machine only. Every address the name resolves to must be inside one
   *  of them, at launch and at every connection. */
  readonly perimeter?: readonly string[];
  /** Plan 12 D4: the host is (under) one of `perimeter.domains`: words only. */
  readonly orgDomain?: true;
  /** Plan 12 D5: the administrator's file that set this entry. */
  readonly adminFile?: string;
  /** Plan 12 D5: set by the administrator and locked (`models_locked`): the
   *  user may remove it, not change it. */
  readonly locked?: true;
}

function compileModels(entries: readonly EffectiveModelEntry[] | undefined, perimeter: Perimeter | null, locked: boolean): readonly ModelEndpoint[] {
  const out: ModelEndpoint[] = [];
  const seen = new Set<string>();
  for (const e of entries ?? []) {
    if (typeof e?.name !== "string" || typeof e?.url !== "string" || seen.has(e.name)) continue;
    seen.add(e.name);
    out.push(Object.freeze({
      name: e.name,
      url: e.url,
      wire: e.wire === "openai-chat" ? "openai-chat" : "anthropic",
      ...(typeof e.model === "string" ? { model: e.model } : {}),
      local: e.local === true, // only the literal true declares a local model
      ...(typeof e.token_env === "string" ? { tokenEnv: e.token_env } : {}),
      ...(e.helper === true && e.local === true ? { helper: true as const } : {}),
      ...(e.allow_plain_http === true ? { allowPlainHttp: true as const } : {}),
      ...((): { tls?: ModelTls } => { const t = compileModelTls(e); return t ? { tls: t } : {}; })(),
      ...(perimeterApplies(e, perimeter) ? { perimeter: perimeter.networks } : {}),
      ...(perimeter !== null && endpointPlacement(e.url) === "network" && domainMatches(urlHost(e.url) ?? "", perimeter.domains) ? { orgDomain: true as const } : {}),
      ...(typeof e.adminFile === "string" ? { adminFile: e.adminFile, ...(locked ? { locked: true as const } : {}) } : {}),
    }));
  }
  return Object.freeze(out);
}

/**
 * Where the named endpoint runs, from the law in force (plan 11 D2/D4):
 * `local` only for a declared `local: true` entry; an absent name, an
 * unknown name, or a declared `local: false` entry is `external`.
 */
export function modelLocation(models: readonly ModelEndpoint[], name: string | undefined): ModelLocation {
  if (typeof name !== "string") return "external";
  return models.some((m) => m.name === name && m.local) ? "local" : "external";
}

/**
 * The declared model tokens (policy.yaml models[].token_env, plan 11 D2) and
 * the hosts each may be sent to without an ask: the host of every entry that
 * names it. The arbiter registers each name as an environment secret whatever
 * the name looks like, so the agent's environment carries it masked. An IPv6
 * literal gets no binding (a binding is a host name), so the token is still
 * masked and any send of it asks.
 */
export function modelTokenBindings(models: readonly ModelEndpoint[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const m of models) {
    if (m.tokenEnv === undefined) continue;
    const hosts = out.get(m.tokenEnv) ?? [];
    let host = "";
    try { host = new URL(m.url).hostname.toLowerCase(); } catch { /* validated at load */ }
    if (host !== "" && !host.startsWith("[") && !hosts.includes(host)) hosts.push(host);
    out.set(m.tokenEnv, hosts);
  }
  return out;
}

/** One reachability rule, lists expanded, defaults applied (port 443, tcp). */
export interface CompiledDestination {
  readonly host: string;
  readonly port: number | "*";
  readonly proto: "tcp" | "udp";
  readonly connect: "allow" | "deny";
  readonly reason?: string;
}

/** The connect-guard allow specs (`proto:host:port`) the launcher appends to
 *  its guard set WITHOUT dropping the permissive fallback (net-guard.ts
 *  `extraAllow`). Only `connect: allow` rules contribute; deduplicated. */
export function connectAllowSpecs(compiled: CompiledPolicy): string[] {
  const out: string[] = [];
  for (const d of compiled.destinations) {
    if (d.connect !== "allow") continue;
    const spec = `${d.proto}:${d.host}:${d.port}`;
    if (!out.includes(spec)) out.push(spec);
  }
  return out;
}

const LIST_REF = /^@([A-Za-z0-9_.-]+)$/;

function expandRefs(values: readonly string[] | undefined, lists: Record<string, string[]>): string[] | undefined {
  if (!values) return undefined;
  const out: string[] = [];
  for (const v of values) {
    const m = LIST_REF.exec(v);
    if (m) out.push(...(lists[m[1]!] ?? []));
    else out.push(v);
  }
  return out;
}

/**
 * The document with every `@list` reference in the origin lists replaced by
 * the list's members (pure; the input is not modified). The origin-classifier
 * registry consumes the result directly; `compilePolicy` expands user rules
 * itself so their references keep their `@name` in the snapshot.
 */
export function expandListsInDocument(doc: PolicyFileConfig | null): PolicyFileConfig | null {
  if (!doc) return doc;
  const lists = doc.lists ?? {};
  if (!doc.inbound) return doc;
  const inbound = { ...doc.inbound };
  for (const cat of ["url", "channel", "dir"] as const) {
    const c = inbound[cat];
    if (!c) continue;
    inbound[cat] = {
      ...c,
      ...(c.trustedList ? { trustedList: expandRefs(c.trustedList, lists) } : {}),
      ...(c.untrustedList ? { untrustedList: expandRefs(c.untrustedList, lists) } : {}),
    };
  }
  return { ...doc, inbound };
}

/** Map key of a pattern label: never a possible normalized path. */
export const GLOB_KEY_PREFIX = "glob:";

/** A literal entry may escape a metacharacter (`\*`) to stay literal; the
 *  label store is keyed by the real path, so drop the escapes. */
function unescapeLiteral(raw: string): string {
  return typeof raw === "string" ? raw.replace(/\\([*?\[\]\\])/g, "$1") : raw;
}

/** The compiled `env:` section (plan 10 §11.4). */
export interface EnvSecretRules {
  readonly secrets: readonly string[];
  readonly exempt: readonly string[];
}

export interface CompiledEnvSource {
  readonly name: string;
  readonly source: string;
  readonly bindings: readonly string[];
}

function compileEnv(entry: EnvSecretsEntry | undefined): EnvSecretRules {
  const names = (l: unknown): string[] => (Array.isArray(l) ? l.filter((n): n is string => typeof n === "string" && n !== "" && n !== "*") : []);
  return Object.freeze({ secrets: Object.freeze(names(entry?.secrets)), exempt: Object.freeze(names(entry?.exempt)) });
}

function compileApps(entries: readonly AppEntry[] | undefined): Map<string, AppRule> {
  const out = new Map<string, AppRule>();
  for (const e of entries ?? []) {
    if (typeof e.app !== "string") continue;
    if (e.output !== "secret" && appRuleRefusal({ app: e.app, output: e.output })) continue; // the validator refused these at boot
    out.set(e.app, { app: e.app, output: e.output, ...(e.mask ? { mask: [...e.mask] } : {}) });
  }
  return out;
}

function compilePathLabels(entries: readonly PathLabelEntry[] | undefined): Map<string, PathLabel> {
  const out = new Map<string, PathLabel>();
  const compiledAt = Date.now(); // "as of this compile" — the file has no per-row clock
  for (const e of entries ?? []) {
    // The validator refuses an unknown level at boot and on every reload. A
    // loader that skipped it must still not turn a lock into nothing: an
    // entry whose level is missing or unknown locks at the strictest level.
    const level = isConfidentialityLevel(e.level) ? e.level : "no-model";
    const common = {
      confidentiality: level,
      bindings: [...(e.bindings ?? [])],
      recursive: e.recursive ?? true,
      source: "policy-file" as const,
      updatedAt: compiledAt,
      ...(typeof e.extract === "string" && e.extract !== "" ? { extract: e.extract } : {}),
      ...(Array.isArray(e.readers) ? { readers: [...e.readers] } : {}),
      ...(e.others ? { others: e.others } : {}),
      ...(() => { const values = compileValueRules(e.values); return values ? { values } : {}; })(),
    };
    if (typeof e.path === "string" && hasGlobMeta(e.path)) {
      // A PATTERN (path-glob.ts). Keyed apart from the literals (`glob:` cannot
      // start a normalized path), so a literal label on a path whose text
      // happens to equal a pattern can never replace it in a merged map.
      const r = compilePathGlob(e.path);
      if (!("glob" in r)) continue; // the validator refused these at boot
      out.set(GLOB_KEY_PREFIX + r.glob.pattern, { path: r.glob.pattern, ...common, glob: true });
      continue;
    }
    const p = normalizeLabelPath(unescapeLiteral(e.path));
    if (p === null) continue; // the validator refused these at boot
    out.set(p, { path: p, ...common });
  }
  return out;
}

/**
 * The product Rules page's row ids for ONE policy.yaml item (a section + key +
 * value as `policy-edit.ts` itemizes the document), in the vocabulary of the
 * dashboard's `yourRulesVM` (policy-panel.ts): `lock:<path>`, `app:<name>`, a
 * user rule's id, `connect:<proto>:<host>:<port>`, `disposition:<rule>`,
 * `trusted-origin:<cat>:<value>`. Compiled exactly as the law compiles it
 * (a path normalized, a list reference expanded), so the dashboard can join a
 * recorded change to the row it wrote without re-implementing either
 * (dashboard.md §4.25i). Attribution only; empty for an item no row shows.
 */
export function panelRowIds(section: string, key: string, value: unknown, lists: Record<string, string[]>): string[] {
  if (value === null || value === undefined) return [];
  switch (section) {
    case "paths":
      return [...compilePathLabels([value as PathLabelEntry]).values()].map((l) => `lock:${l.path}`);
    case "apps":
      return [`app:${key}`];
    case "user_rules":
      return [key];
    case "destinations":
      return compileDestinations([value as DestinationEntry], lists).map((d) => `connect:${d.proto}:${d.host}:${d.port}`);
    case "rules":
      return [`disposition:${key}`];
    case "origin": {
      const [cat, member] = key.split("\0");
      const v = value as { trusted?: boolean; untrusted?: boolean };
      const kind = v.trusted ? "trusted-origin" : v.untrusted ? "untrusted-origin" : null;
      if (!kind || !cat || member === undefined) return [];
      return (expandRefs([member], lists) ?? []).map((m) => `${kind}:${cat}:${m}`);
    }
    default:
      return [];
  }
}

function hostList(v: string | undefined, lists: Record<string, string[]>): string[] | null {
  if (v === undefined) return null;
  const expanded = expandRefs([v], lists) ?? [];
  return expanded.map((h) => h.trim().toLowerCase()).filter(Boolean);
}

function compileDestinations(entries: readonly DestinationEntry[] | undefined, lists: Record<string, string[]>): CompiledDestination[] {
  const out: CompiledDestination[] = [];
  for (const d of entries ?? []) {
    for (const host of hostList(d.host, lists) ?? []) {
      out.push({
        host,
        port: d.port ?? 443,
        proto: d.proto ?? "tcp",
        connect: d.connect,
        ...(d.reason !== undefined ? { reason: d.reason } : {}),
      });
    }
  }
  return out;
}

function compileUserRules(entries: readonly UserRuleEntry[] | undefined, lists: Record<string, string[]>): CompiledUserRule[] {
  return (entries ?? []).map((r) => ({
    id: r.id,
    kind: "release",
    from: r.from?.host === undefined ? null : hostList(r.from.host, lists),
    to: hostList(r.to.host, lists) ?? ["*"],
    mode: r.mode,
    ...(r.reason !== undefined ? { reason: r.reason } : {}),
    ...(r.by !== undefined ? { by: r.by } : {}),
    ...(r.added !== undefined ? { added: r.added } : {}),
    expiresAt: r.expires ? Date.parse(r.expires) : null,
  }));
}

/** Case-insensitive host match: exact, or a `*.example.com` suffix pattern
 *  (which also matches `example.com` itself); "*" matches everything. */
export function hostMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === "*") return true;
  if (p.startsWith("*.")) {
    const bare = p.slice(2);
    return h === bare || h.endsWith("." + bare);
  }
  return p === h;
}

export interface UserRuleMatchInput {
  /** The origin host of the symbol (from its URL origin), or null when unknown. */
  originHost: string | null;
  destinationHost: string;
  now?: number;
}

export interface UserRuleVerdict {
  /** The deciding rule, or null when no active rule matched. */
  decision: { mode: "allow" | "block"; rule: CompiledUserRule } | null;
  /** Audit-mode rules that matched and would have decided. */
  audited: CompiledUserRule[];
}

/**
 * The user-rule step of the egress gate (§2.4 precedence): among the active
 * (not off, not expired) rules whose `from` and `to` match, **Block beats
 * Allow**; audit rules are reported, never applied. A rule with `from` set
 * matches only when the origin host is KNOWN and matches — an unknown origin
 * never satisfies a narrowed rule (fail-closed toward asking).
 */
export function matchUserRules(compiled: CompiledPolicy, input: UserRuleMatchInput): UserRuleVerdict {
  const now = input.now ?? Date.now();
  const dest = input.destinationHost.toLowerCase();
  const origin = input.originHost?.toLowerCase() ?? null;
  const audited: CompiledUserRule[] = [];
  let allow: CompiledUserRule | null = null;
  let block: CompiledUserRule | null = null;
  for (const r of compiled.userRules) {
    if (r.mode === "off") continue;
    if (r.expiresAt !== null && now >= r.expiresAt) continue;
    if (!r.to.some((p) => hostMatches(p, dest))) continue;
    if (r.from !== null) {
      if (origin === null) continue;
      if (!r.from.some((p) => hostMatches(p, origin))) continue;
    }
    if (r.mode === "audit") audited.push(r);
    else if (r.mode === "block") block ??= r;
    else allow ??= r;
  }
  const decision = block ? { mode: "block" as const, rule: block } : allow ? { mode: "allow" as const, rule: allow } : null;
  return { decision, audited };
}

/** The host of a symbol's origin: URL origins yield their hostname; anything
 *  else (a file path, a channel id, null) yields null. */
export function originHostOf(origin: string | null | undefined): string | null {
  if (!origin) return null;
  try {
    const u = new URL(origin);
    return u.hostname ? u.hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

export interface CompilePolicyInput {
  specId: InboundSpecId;
  document: PolicyFileConfig | null;
  lawSource?: PolicyLawSource;
  log?: CompileLogger;
  /** Plan 12 D5: the administrator's layer (default: the one in force). */
  admin?: AdminLayer;
}

type InboundTables = Record<InboundSpecId, Record<string, ToolSpec>>;
type ResolveTables = Record<InboundSpecId, Record<string, boolean>>;
type FieldTables = Record<InboundSpecId, Record<string, Record<string, InputFieldPolicy>>>;

function copyInbound(): InboundTables {
  const out = {} as InboundTables;
  for (const id of INBOUND_SPEC_IDS) out[id] = { ...BUILTIN_INBOUND_SPECS[id] };
  return out;
}

function copyResolve(): ResolveTables {
  const out = {} as ResolveTables;
  for (const id of INBOUND_SPEC_IDS) out[id] = { ...BUILTIN_OUTBOUND_RESOLVE[id] };
  return out;
}

function copyFieldPolicy(): FieldTables {
  const out = {} as FieldTables;
  for (const id of INBOUND_SPEC_IDS) {
    const c: Record<string, Record<string, InputFieldPolicy>> = {};
    for (const [tool, fields] of Object.entries(BUILTIN_OUTBOUND_FIELD_POLICY[id])) c[tool] = { ...fields };
    out[id] = c;
  }
  return out;
}

function freezeTables<T extends object>(tables: Record<InboundSpecId, T>): Readonly<Record<InboundSpecId, Readonly<T>>> {
  for (const id of INBOUND_SPEC_IDS) Object.freeze(tables[id]);
  return Object.freeze(tables);
}

/** Pure: (spec id, document) → the law, frozen. Never touches the built-ins. */
export function compilePolicy(input: CompilePolicyInput): CompiledPolicy {
  const log = input.log ?? SILENT;
  // The document is kept AS WRITTEN (same reference; `@list` refs intact for
  // the snapshot); the origin-classifier registry receives the expanded copy
  // from createEngineBackedPolicy, and user rules expand their own refs below.
  const document = input.document;
  const specId = input.specId;
  const lists: Record<string, string[]> = {};
  for (const [name, values] of Object.entries(input.document?.lists ?? {})) lists[name] = [...values];

  const inbound = copyInbound();
  const outboundResolve = copyResolve();
  const outboundFieldPolicy = copyFieldPolicy();

  // Tool overrides apply to the boot spec's tables only — the semantics the
  // in-place merge always had (a session bound to the same id sees them).
  const applied = applyToolOverrides(
    { inbound: inbound[specId], outboundResolve: outboundResolve[specId], outboundFieldPolicy: outboundFieldPolicy[specId] },
    document?.tools,
    log,
  );
  inbound[specId] = applied.inbound;
  outboundResolve[specId] = applied.outboundResolve;
  outboundFieldPolicy[specId] = applied.outboundFieldPolicy;

  const execIndex = applyCommandOverrides(BUILTIN_EXEC_RESULT_TRUST_ENTRIES, document?.inbound?.command ?? [], log);
  const lawSource: PolicyLawSource = input.lawSource ?? (document ? { kind: "custom" } : { kind: "builtin" });

  const dispositions: Record<string, "ask" | "block"> = {};
  for (const [id, d] of Object.entries(document?.rules ?? {})) dispositions[id] = d.mode;
  // Plan 12 D5: the administrator's models and perimeter under the user's.
  const admin = input.admin ?? getAdminLayer();
  const effective = effectiveModels(document, admin);

  return Object.freeze({
    specId,
    inbound: freezeTables(inbound),
    outboundResolve: freezeTables(outboundResolve),
    outboundFieldPolicy: freezeTables(outboundFieldPolicy),
    execIndex: Object.freeze(execIndex),
    lists: Object.freeze(lists),
    pathLabels: compilePathLabels(document?.paths),
    blobLocks: compileBlobLocks(document?.blobs),
    dispositions: Object.freeze(dispositions),
    apps: compileApps(document?.apps),
    envSecrets: compileEnv(document?.env),
    protect: Object.freeze((document?.protect ?? []).filter((p): p is string => typeof p === "string")),
    mappedTools: compileMappedTools(document?.mapped_tools),
    issuerBindings: compileIssuerBindings(document?.issuer_bindings),
    models: compileModels(effective.models, compilePerimeter(effective.perimeter), admin.locked),
    perimeter: compilePerimeter(effective.perimeter),
    admin: hasAdminLayer(admin)
      ? Object.freeze({ dir: admin.dir, files: admin.files, locked: admin.locked, perimeterFile: admin.perimeterFile })
      : null,
    sshAgentReaders: Array.isArray(document?.ssh_agent?.readers) ? Object.freeze([...document!.ssh_agent!.readers]) : null,
    envSources: Object.freeze((document?.env?.sources ?? [])
      .filter((e) => typeof e?.name === "string" && typeof e?.source === "string")
      .map((e) => Object.freeze({ name: e.name, source: e.source, bindings: Object.freeze([...(e.bindings ?? [])]) }))),
    userRules: Object.freeze(compileUserRules(document?.user_rules, lists)),
    destinations: Object.freeze(compileDestinations(document?.destinations, lists)),
    document,
    lawSource,
  });
}

// ── the law in force ─────────────────────────────────────────────────────────

let current: CompiledPolicy | undefined;

/** The compiled law every accessor reads. Lazily compiles the built-in
 *  `claude-code` law on first use (so module import order never matters). */
export function getCurrentPolicy(): CompiledPolicy {
  return (current ??= compilePolicy({ specId: "claude-code", document: null }));
}

/** Atomically make `next` the law in force. */
export function swapCurrentPolicy(next: CompiledPolicy): CompiledPolicy {
  current = next;
  return next;
}

/** Recompile the current document under another boot spec (the
 *  `setActiveInboundSpec` path) — the document and law source are kept. */
export function recompileCurrentWithSpec(specId: InboundSpecId): CompiledPolicy {
  const c = getCurrentPolicy();
  return swapCurrentPolicy(compilePolicy({ specId, document: c.document, lawSource: c.lawSource }));
}

/** Back to the built-in law under the current spec (tests). */
export function resetCurrentPolicyForTests(specId?: InboundSpecId): void {
  current = compilePolicy({ specId: specId ?? getCurrentPolicy().specId, document: null });
}

// ── relaxations ──────────────────────────────────────────────────────────────

export type RelaxationKind =
  | "inbound-trust" // a tool result field the document marks TRUSTED that the built-ins did not
  | "outbound-resolve" // a tool/field the document lets desymbolize (HumanView) that the built-ins did not
  | "trusted-origin" // an allow-listed origin (URL/CHANNEL/DIR trustedList entry)
  | "exec-output-trust" // a command whose output the document trusts more than the built-ins
  | "user-rule-allow" // a release rule (user_rules, mode allow) that lets untrusted data leave without an ask
  | "public-path" // a locked-file label at `public` — a declassification if the catalog says secret
  | "public-blob" // a blob lock at `public`: it hides nothing (plan 14 §8.2); the object is declared not secret
  | "connect-allow" // a destination the agent's processes may reach in every launch posture (destinations:, §2.3 4b)
  | "path-binding" // a locked file released to a destination without an ask (paths: bindings, a standing release)
  | "env-exempt" // an environment variable the built-in shapes would mask that reaches the agent in the clear (env: exempt)
  | "pack-consumer" // a signed consumer pack lets a program read a secret file raw by default (consumer-packs.ts)
  | "env-binding" // a sourced environment variable that may be sent to its bound hosts without an ask (env: sources[].bindings)
  | "app-output"; // a reader whose output stays readable after it read ONE file (paths[].readers[].output clear | mask, plan 13 D3)

export interface Relaxation {
  kind: RelaxationKind;
  /** What is relaxed: `tool.path`, `tool`, `URL:https://…`, `git:trustHelp`. */
  subject: string;
  detail: string;
}

function trustedLeafPaths(node: SchemaNode | undefined, prefix = ""): Set<string> {
  const out = new Set<string>();
  if (node === undefined) return out;
  if (typeof node === "string") {
    if (node === "TRUSTED") out.add(prefix || "*");
    return out;
  }
  if (typeof node !== "object" || node === null) return out;
  if ("role" in node) return out; // a marker is conditional, never a flat grant
  if ("__items" in node) {
    for (const p of trustedLeafPaths((node as { __items: SchemaNode }).__items, prefix ? `${prefix}[]` : "[]")) out.add(p);
    return out;
  }
  for (const [k, v] of Object.entries(node as Record<string, SchemaNode>)) {
    for (const p of trustedLeafPaths(v, prefix ? `${prefix}.${k}` : k)) out.add(p);
  }
  return out;
}

function specTrustedPaths(spec: ToolSpec | undefined): Set<string> {
  if (!spec) return new Set();
  if (isActionSpec(spec)) {
    const out = new Set<string>();
    for (const [action, schema] of Object.entries(spec.schemas)) {
      for (const p of trustedLeafPaths(schema, `[${action}]`)) out.add(p);
    }
    for (const p of trustedLeafPaths(spec.defaultSchema, "[default]")) out.add(p);
    return out;
  }
  const out = trustedLeafPaths(spec.schema);
  if (spec.wholeResult === "TRUSTED") out.add("*");
  return out;
}

/**
 * Every way `compiled` is more permissive than the built-ins under its boot
 * spec. Empty for a built-in compile — a test pins that. Pure.
 */
export function relaxationsOf(compiled: CompiledPolicy): Relaxation[] {
  const out: Relaxation[] = [];
  const id = compiled.specId;
  const builtinInbound = BUILTIN_INBOUND_SPECS[id];
  for (const [tool, spec] of Object.entries(compiled.inbound[id])) {
    if (spec === builtinInbound[tool]) continue; // untouched built-in object
    const before = specTrustedPaths(builtinInbound[tool]);
    for (const p of specTrustedPaths(spec)) {
      if (!before.has(p)) out.push({ kind: "inbound-trust", subject: `${tool}.${p}`, detail: `the document marks ${tool} ${p === "*" ? "(whole result)" : p} TRUSTED; the built-ins did not` });
    }
  }
  const builtinResolve = BUILTIN_OUTBOUND_RESOLVE[id];
  for (const [tool, resolves] of Object.entries(compiled.outboundResolve[id])) {
    if (resolves && !builtinResolve[tool]) out.push({ kind: "outbound-resolve", subject: tool, detail: `${tool} may desymbolize (HumanView) — the built-ins kept it AgentView` });
  }
  const builtinFields = BUILTIN_OUTBOUND_FIELD_POLICY[id];
  for (const [tool, fields] of Object.entries(compiled.outboundFieldPolicy[id])) {
    for (const [field, policy] of Object.entries(fields)) {
      if (policy === "resolve" && builtinFields[tool]?.[field] !== "resolve") {
        out.push({ kind: "outbound-resolve", subject: `${tool}.${field}`, detail: `${tool}.${field} resolves symbols — the built-ins did not` });
      }
    }
  }
  // Origin lists as the classifier registry saw them: `@list` refs expanded.
  const inbound = expandListsInDocument(compiled.document)?.inbound;
  for (const cat of ["url", "channel", "dir"] as const) {
    for (const v of inbound?.[cat]?.trustedList ?? []) {
      out.push({ kind: "trusted-origin", subject: `${cat.toUpperCase()}:${v}`, detail: `${cat.toUpperCase()} origin ${v} is trusted — its data enters the model unmasked` });
    }
  }
  for (const v of inbound?.["url-trust"]?.trustedUrls ?? []) {
    out.push({ kind: "trusted-origin", subject: `URL:${v}`, detail: `URL origin ${v} is trusted (legacy url-trust) — its data enters the model unmasked` });
  }
  // Reachability (§2.3, 4b): an extra connect allow widens what the agent's
  // processes may reach in EVERY launch posture — in the permissive default
  // only beyond :443/:22, under strict/curated for every listed destination.
  for (const spec of connectAllowSpecs(compiled)) {
    out.push({ kind: "connect-allow", subject: spec, detail: `the agent's processes may connect to ${spec} in every launch posture (strict/curated included) — applies at the next launch` });
  }
  for (const entry of inbound?.command ?? []) {
    const before = BUILTIN_EXEC_RESULT_TRUST_ENTRIES[entry.id];
    if (entry.trustErrors && !before?.trustErrors) out.push({ kind: "exec-output-trust", subject: `${entry.id}:trustErrors`, detail: `${entry.id}'s error output is trusted` });
    if (entry.trustHelp && !before?.trustHelp) out.push({ kind: "exec-output-trust", subject: `${entry.id}:trustHelp`, detail: `${entry.id}'s --help output is trusted` });
    const beforePaths = trustedLeafPaths(before?.schema);
    for (const p of trustedLeafPaths(entry.schema as SchemaNode | undefined)) {
      if (!beforePaths.has(p)) out.push({ kind: "exec-output-trust", subject: `${entry.id}.${p}`, detail: `${entry.id} output ${p} is trusted` });
    }
    for (const [sub, s] of Object.entries(entry.subcommands ?? {})) {
      const beforeSub = trustedLeafPaths(before?.subcommands?.[sub]?.schema);
      for (const p of trustedLeafPaths(s.schema as SchemaNode | undefined)) {
        if (!beforeSub.has(p)) out.push({ kind: "exec-output-trust", subject: `${entry.id} ${sub}.${p}`, detail: `${entry.id} ${sub} output ${p} is trusted` });
      }
    }
  }
  for (const r of compiled.userRules) {
    if (r.mode !== "allow") continue; // block tightens; audit/off decide nothing
    const from = r.from === null ? "any origin" : r.from.join(", ");
    out.push({
      kind: "user-rule-allow",
      subject: r.id,
      detail: `user rule ${r.id}: untrusted data from ${from} may leave to ${r.to.join(", ")} without an ask${r.expiresAt ? " (expires)" : ""}`,
    });
  }
  for (const l of compiled.pathLabels.values()) {
    if (l.confidentiality === "public") {
      out.push({ kind: "public-path", subject: l.path, detail: `${l.path} is labeled public — a declassification wherever the secret catalog would have said otherwise` });
    } else if (l.bindings.length > 0) {
      out.push({ kind: "path-binding", subject: l.path, detail: `${l.path} (${l.confidentiality}) may be sent to ${l.bindings.join(", ")} without an ask` });
    }
    // Plan 13 §5.2: each value bound on its own is a standing release too.
    if (l.confidentiality !== "public") {
      for (const v of l.values ?? []) {
        if (v.bindings.length > 0) out.push({ kind: "path-binding", subject: `${l.path} ${v.key}`, detail: `${v.key} in ${l.path} (${l.confidentiality}) may be sent to ${v.bindings.join(", ")} without an ask` });
      }
    }
  }
  for (const b of compiled.blobLocks.values()) {
    if (b.level === "public") out.push({ kind: "public-blob", subject: b.id, detail: `the repository object ${b.id} is labeled public: it is not hidden from the agent (a label on a file that held it still hides it)` });
  }
  for (const name of compiled.envSecrets.exempt) {
    out.push({ kind: "env-exempt", subject: name, detail: `environment variable ${name} reaches the agent in the clear even where its name looks like a secret` });
  }
  for (const src of compiled.envSources) {
    if (src.bindings.length > 0) out.push({ kind: "env-binding", subject: src.name, detail: `environment variable ${src.name} (from ${src.source.split(":")[0]}) may be sent to ${src.bindings.join(", ")} without an ask` });
  }
  // Plan 13 D3: an output rule is a reader entry's, on one file. The
  // program-wide `apps:` table is deprecated and clears nothing, so it is no
  // relaxation (policyDelta still classifies its edits, fail-closed).
  for (const l of compiled.pathLabels.values()) {
    for (const r of l.readers ?? []) {
      if (typeof r === "string" || r.output === undefined || r.output === "secret") continue;
      if (readerOutputRefusal(r.app, r.output, r.script) !== null) continue; // the validator refused these at boot
      // Plan 13 R5: an interpreter pinned with its script is that program.
      const who = r.script !== undefined ? `${r.app} running ${r.script}` : r.app;
      out.push({
        kind: "app-output", subject: `${who} on ${l.path}`,
        detail: r.output === "clear"
          ? `${who}'s output is shown to the model in the clear after it read ${l.path}`
          : `${who}'s output is shown after it read ${l.path}, with only the listed spans masked`,
      });
    }
  }
  return out;
}
