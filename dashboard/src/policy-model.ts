/**
 * policy-model — the dashboard's structural mirror of the arbiter policy SNAPSHOT.
 *
 * Mandu-new (NO reference origin). The arbiter serializes its ACTIVE data-trust
 * (inbound schema) + data-usage (outbound resolve/egress) + origin rules via the
 * `policySnapshot` IPC op (arbiter/policy/policy-snapshot.ts). The dashboard reads
 * it (GET /api/policy) and renders it in the per-tool-call policy modal, joined
 * by tool name with the per-call decision already on each event (EventPolicy).
 *
 * Like event-model.ts, the dashboard keeps its OWN structural copy of the shape
 * rather than importing the arbiter package (the packages install + typecheck
 * independently — see CONTRIBUTING.md). The snapshot is OBSERVABILITY data rendered
 * as-is; this module adds no behavior, only the type + a small lookup helper.
 */

export type Trust = "TRUSTED" | "UNTRUSTED";
export type FieldTrust = Trust | "conditional";

export interface OriginRule {
  id: string;
  mode: "allowlist" | "blocklist";
  listSize: number;
  defaultTrust: Trust;
}

export interface InboundFieldRule {
  field: string;
  trust: FieldTrust;
  category: string | null;
  detail: string;
}

export interface InboundRule {
  kind: "literal" | "structured" | "action";
  summary: string;
  fields: InboundFieldRule[];
}

export interface OutboundFieldRule {
  field: string;
  policy: "resolve" | "not_resolve" | "no_symbols_expected";
}

export interface OutboundRule {
  toolResolve: boolean;
  destination: "HumanView" | "AgentView";
  summary: string;
  fields: OutboundFieldRule[];
}

export interface ToolRule {
  tool: string;
  inbound: InboundRule | null;
  outbound: OutboundRule;
}

export interface PolicySnapshot {
  specId: string;
  origins: OriginRule[];
  tools: Record<string, ToolRule>;
  fallbackTrust: "UNTRUSTED";
  mcpPrefix: string;
  /** ── Server-composed standing state (policy-surface.md §9.4, §9.8) ──────────
   * ALL OPTIONAL: an arbiter predating the extension omits them, and the
   * Policy panel must render that as UNKNOWN/unavailable — never as "off" or
   * an empty allow-list (the posture-guard lesson). */
  posture?: { integrity: boolean; confidentiality: boolean };
  usage?: { rules: UsageRuleRow[]; sensitivePaths: string[]; gates?: UsageGateRow[] };
  verdicts?: VerdictEntry[];
  /** SIEM-lockdown egress posture (siem-integration.md §4.3). Absent on
   * arbiters predating it — rendered "unknown", never "normal". */
  egressPosture?: "normal" | "lockdown";
  /** Where the active policy came from (§8 "law source"). Absent on older
   * arbiters — the panel omits the line rather than inventing provenance. */
  lawSource?: LawSourceRow;
  /** The operator's law from policy.yaml (policy-surface.md §2.1,
   * stage 4): named lists, locked-file labels, dispositions and user rules —
   * plus the relaxations it introduces and per-rule hit counts. Absent on
   * arbiters predating stage 4; rendering arrives with the Policy area. */
  document?: PolicyDocumentRow;
  relaxations?: RelaxationRow[];
  hits?: Record<string, { hits: number; auditHits: number; lastHit: number | null }>;
  /** The policy FILE's status (stage 5a): `valid:false` = the file on disk is
   * refused and the last-known-good law is in force — render a banner. */
  policyFile?: {
    path: string | null;
    found: boolean;
    valid: boolean;
    problems: string[];
    loadedAt: number | null;
    refusedAt: number | null;
  };
}

export interface PolicyDocumentRow {
  /** (see arbiter protocol PolicySnapshotOpResult.document) */
  lists: Record<string, string[]>;
  /** `readersAdmitNothing`, `readersReadTwin`, `readersCopyOf`: the
   *  arbiter's judgment of each `readers` entry, in its order (Plan 13 D8
   *  (13), P0 item 14); absent on an older arbiter, whose rows the name
   *  rule judges. */
  paths: {
    path: string; level: string; bindings: string[]; recursive: boolean;
    readers?: Array<string | { app: string; path?: string; sha256?: string; from?: string; output?: "secret" | "clear" | "mask"; mask?: string[]; script?: string; scriptSha256?: string; prints?: "nothing" }>;
    readersAdmitNothing?: boolean[]; readersReadTwin?: boolean[]; readersCopyOf?: Array<string | null>;
    others?: "deny" | "twin"; extract?: string;
    /** Plan 13 §5.2: per-value bindings, and where the whole file may go
     *  (the intersection, as the arbiter computes it; absent ⇒ nowhere);
     *  absent on an older arbiter. */
    values?: Array<{ key: string; bindings: string[] }>;
    wholeBindings?: string[];
  }[];
  /** Plan 10 §2.2: per-app output rules once tainted. Absent on an older arbiter.
   *  DEPRECATED (plan 13 D3): clears nothing; the rule is a reader entry's. */
  apps?: { app: string; output: "secret" | "clear" | "mask"; mask?: string[] }[];
  rules: Record<string, { mode: string }>;
  userRules: {
    id: string; kind: string; from: string[] | null; to: string[]; mode: string;
    reason?: string; by?: string; added?: string; expires?: string | null;
  }[];
  /** Reachability rules (policy-surface.md §2.3, stage 4b): the
   *  agent's processes may connect there at the next launch. Absent on an
   *  arbiter predating 4b. */
  destinations?: { host: string; port: number | "*"; proto: "tcp" | "udp"; connect: "allow" | "deny"; reason?: string }[];
  /** Plan 11 D2: declared model endpoints (policy.yaml `models:`). Absent on
   *  an arbiter predating plan 11, or [] when none are declared. `tokenEnv`
   *  is the NAME of the env var holding the token, never its value. */
  models?: { name: string; url: string; wire: "anthropic" | "openai-chat"; model?: string; local: boolean; tokenEnv?: string; helper?: true }[];
  /** The version of each declared model's entry, by name (policy-surface.md
   *  §8.4.6 "An item-level version"): Settings › Models' update sends it
   *  back and is refused as stale once the entry changed. Absent on an
   *  older arbiter. */
  modelVersions?: Record<string, string>;
  /** The version of each file rule's entry, by `paths[].path` as listed
   *  (policy-surface.md §8.4.6 "An item-level version"): the Rules page's
   *  label buttons send it back with the change, refused as stale once the
   *  rule changed. Absent on an older arbiter. */
  pathVersions?: Record<string, string>;
  /** Plan 12 D4: the perimeter in force, and who set its networks
   *  (`narrowed`: the user narrowed the administrator's). */
  perimeter?: { networks: string[] | null; domains: string[]; by: "administrator" | "you" | "narrowed" };
  /** Plan 12 D5: the administrator's layer, when one is in force (or a
   *  re-read of it was refused): the user's entries it keeps out of force,
   *  and the administrator's entries the user removed. */
  modelsAdmin?: { files: string[]; locked: boolean; conflicts?: string[]; refused?: string[]; removed?: Array<{ name: string; file: string }> };
}

export interface RelaxationRow {
  kind: string;
  subject: string;
  detail: string;
}

/** Mirrors arbiter/policy/rule-ref.ts `UsageGate` (the gate catalog: the
 * "where is this rule specified" citation, shipped from the enforcing code). */
export interface UsageGateRow {
  id: string;
  title: string;
  definedIn: string;
  doc: string;
  evaluation: string;
}

/** Mirrors arbiter/policy/load-policy.ts `PolicyLawSource`. */
export interface LawSourceRow {
  kind: "builtin" | "file" | "custom";
  configuredPath?: string;
  resolvedPath?: string;
  found?: boolean;
  sections?: {
    url: boolean;
    channel: boolean;
    dir: boolean;
    commandEntries: number;
    toolOverrides: number;
  };
}

/** Mirrors arbiter/policy/rule-ref.ts `UsageRule` (the usage-gate catalog). */
export interface UsageRuleRow {
  id: string;
  source: "rule" | "fail-closed";
  boundary: "filesystem" | "network" | "shell" | "model_context" | "any";
  outcome: "allow" | "deny" | "deny+approval";
  summary: string;
  /** Owning gate (the id's prefix). Optional — an arbiter predating §8 omits
   * it; the view-model derives the prefix instead (deterministic, no drift). */
  gate?: string;
}

/** Mirrors arbiter/policy/egress-approvals.ts `EgressApproval` (same decoupled
 * copy as server/approval-routes.ts — kept here too so the view-model layer
 * types the snapshot without importing route modules). */
export interface VerdictEntry {
  id: string;
  symbol: string;
  destination: string;
  status: "pending" | "approved" | "denied";
  reason: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
  /** Epoch millis of the human resolution; null/absent while pending or for
   * rows resolved before the column existed (policy-surface.md §9.6). */
  resolvedAt?: number | null;
  /** Distinct session keys that created/bumped this entry (most-recent-last,
   * arbiter-capped) — the panel's per-row session links. Absent for rows
   * recorded before the column existed and on old arbiters. */
  sessions?: string[];
  /** The symbol's origin HOST, attached by the arbiter at read time from the
   * symbol table (policy-surface.md §2.5) — the inspector's Approvals "anything
   * from <origin>" offer. Null for a non-URL origin; absent on older arbiters. */
  originHost?: string | null;
  /** Where the symbol's value came from (the symbol table's tool + origin),
   * attached by the arbiter at read time: the Rules page's "which data"
   * (dashboard.md §4.25e). Null for a non-symbol key; absent on older arbiters. */
  source?: { tool: string; origin: string | null } | null;
  /** Verdict scope (policy-surface.md §9.8.7): "always" = standing (the
   * default), "once" = spent by one gated decision. Absent on a pre-scope
   * arbiter, whose verdicts were all standing. */
  scope?: "once" | "always";
  /** Epoch millis a once-scoped verdict was spent, or null/absent. */
  consumedAt?: number | null;
  /** A waiting prompt hold under a LOCKED administrator's `ask` row,
   * attached by the arbiter at read time (plan 15 §12, 2026-10-04): it
   * takes an answer for this message only, and the arbiter refuses a session
   * answer. Absent otherwise and on older arbiters. */
  onceOnly?: boolean;
  /** An ANSWERED verdict about a program that applies to nothing any more,
   * attached by the arbiter at read time (dashboard.md §4.34 "Answers that
   * no longer apply"): named by its name only (before 2026-10-02), about a
   * program that prints what it reads, naming an interpreter alone, or
   * given to a question that did not warn the program may print the file.
   * Absent otherwise and on older arbiters. */
  noLongerApplies?: "name-only" | "printer" | "interpreter" | "unvetted";
  /** A HIGH session's ask (`session-net:` / `session-exec:`,
   * confidentiality.md §4, 2026-10-11): what that session read into the
   * AI's context, as symbols with their origins, attached by the arbiter at
   * read time; `sessionReadsMore` counts the rest. The card names them.
   * Absent on any other row and on older arbiters. */
  sessionReads?: Array<{ symbol: string; origin: string | null }>;
  sessionReadsMore?: number;
  /** A HIGH session's command ask: whether the session's guard holds an
   * allowed run, and the hosts it may then reach (confidentiality.md §4). */
  sessionConfined?: boolean;
  sessionBindings?: string[];
  /** A HIGH session's network ask whose latest request was a HELD
   * command's connection (confidentiality.md §4, "A held command's refused
   * connection", 2026-10-12): the card says the command's request was
   * stopped and Allow once lets the next try through. */
  sessionHeld?: boolean;
  /** A FILE's card (egress-hold.md "One card per file", 2026-10-19): how
   * many protected values of the file its answer covers; attached by the
   * arbiter at read time, two or more. Absent otherwise. */
  fileValues?: number;
  /** A holder's send question (`holder-send:` rows, confidentiality plan
   * 13 §5.4, 2026-10-11): every file the holding program holds as it stands
   * now, where each may go, whether it blocks the destination and whether
   * an *Always* can add the destination to its rule; attached by the arbiter
   * at read time to a pending row. Paths and hosts, never a value. Absent on
   * any other row and on older arbiters. */
  holderSources?: HolderSourceWire[];
  /** "Send without it" (confidentiality.md §4, dashboard.md §4.34): a once
   * denial whose one use sent (or will send) the request with a marker
   * where the secret was. Absent on any other row. */
  strip?: boolean;
  /** A waiting card the arbiter takes "Send without it" on (its read-time
   * mark: a secret's placeholder in a request to a host). Absent on every
   * other row and on older arbiters, which then offer no such button. */
  stripOffered?: boolean;
}

/** One file of a holder's send question, as the arbiter attaches it
 *  (arbiter/policy/holder-send-ask.ts `HolderSource`). */
export interface HolderSourceWire {
  path: string;
  /** The copy the program read, when this file is one of its sources. */
  via?: string;
  /** A folder rule over such a copy, not a file. */
  rule?: true;
  level: string;
  bindings: string[];
  blocks: boolean;
  always: boolean;
  noAlways?: string;
}

/**
 * Resolve the governing rule for a tool name against a snapshot. Exact match
 * wins; otherwise a tool matching the MCP prefix falls back to the synthetic
 * `<prefix>*` rule (mirrors the arbiter's getToolInboundSpec prefix rule). Returns
 * null when the snapshot is absent or the tool is undescribed (→ the caller
 * shows the fail-closed default, snapshot.fallbackTrust).
 */
export function ruleForTool(
  snapshot: PolicySnapshot | null | undefined,
  tool: string | null | undefined,
): ToolRule | null {
  if (!snapshot || !tool) return null;
  const exact = snapshot.tools[tool];
  if (exact) return exact;
  if (snapshot.mcpPrefix && tool.startsWith(snapshot.mcpPrefix)) {
    return snapshot.tools[`${snapshot.mcpPrefix}*`] ?? null;
  }
  return null;
}
