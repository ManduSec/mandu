/**
 * policy-interface — the arbiter's policy boundary.
 *
 * STATUS: the inbound DATA-TRUST path is LIVE (classify, lifted from
 * adfi-openclaw: trust-category / schema-types / resolve-schema / tool-inbound /
 * tool-overrides / load-policy / policy-engine). The outbound DATA-USAGE path is
 * now ALSO LIVE: `desymbolizationDecision()` (the egress gate) is implemented
 * from the lifted outbound spec (tool-outbound) + the exec policy family
 * (exec-identifier / exec-argv-mode / untrusted-command-execution /
 * shell-symbol-resolution / script-file-command-expansion / exec-classify).
 *
 * The classify() interface shape is UNCHANGED so the IPC `classify` op and
 * ipc/server.ts keep working: callers still get `{ trust, category, reason }`.
 *
 * The interface mirrors the two Mandu policies (see docs/design/architecture/mandu.md §1):
 *   - Data trust policy  → classify(): inbound TRUSTED / UNTRUSTED, per field.
 *   - Data usage policy   → desymbolizationDecision(): may a symbol be resolved
 *                           on egress, or does it require human approval?
 *
 * SECURITY-INVARIANT NOTE: classification stays FAIL-CLOSED by default. The
 * engine-backed classify() returns UNTRUSTED whenever (a) the tool has no
 * inbound spec (any tool name absent from the active map — see
 * claude-code-inbound.ts for the Claude Code surface), (b) the referenced field
 * is absent from the tool's schema, (c) a whole-result request hits a
 * structured schema with no explicit `wholeResult` rule, or (d) an
 * origin/schema rule resolves to UNTRUSTED. It only returns TRUSTED on an
 * explicit rule match. So the proxy over-symbolizes when in doubt, never
 * under-symbolizes — the invariant ("untrusted data reaches T-LLM only as a
 * symbol") cannot regress through this engine.
 */

import { withoutGrepExclusions } from "./exclusion-flags.js";
import type { NamedTwin } from "./named-twins.js";
import {
  createPolicyEngine,
  PolicyEngine as TrustCategoryEngine,
} from "./policy-engine.js";
import {
  type ConfidentialityLevel,
  isSecret,
  maxConfidentiality,
  parseConfidentialityLevel,
  parseIntegrityLabel,
} from "../symbol-table/confidentiality.js";
import { resolveConfidentialityEnabled } from "./confidentiality-flag.js";
import { resolveIntegrityEnabled } from "./integrity-flag.js";
import { callWorkdir, labelForClassify, labelForUnmappedInput, resolveTypedPathOrigin, type LabelLookup, type TypedPathBase, type WorkdirTools } from "./secret-catalog.js";
import { gateSurfaceFor } from "./tool-gate-surface.js";
import { describeLawSource, loadPolicyFile, type PolicyFileConfig } from "./load-policy.js";
import { ruleRef, type RuleRef } from "./rule-ref.js";
import { getActiveInboundSpecId, getToolInboundSpec, inboundSpecNamesInput, processSessionSpecs, type SessionSpecLookup } from "./tool-inbound.js";
import { OPENCLAW_AGENT_INBOUND_SPEC, openclawReadRenderingText } from "./openclaw-inbound.js";
import { OPENCODE_INBOUND_SPEC, opencodeReadRenderingText } from "./opencode-inbound.js";
import { GOOSE_INBOUND_SPEC } from "./goose-inbound.js";
import { isOwnWriteNotice, type OwnWriteNoticeAgent } from "./own-write-notice.js";
import { compilePolicy, expandListsInDocument, swapCurrentPolicy } from "./compiled-policy.js";
import { isManduInspectTool } from "./inspect-tool.js";
import { classifyManduPolicyResult, isManduPolicyTool } from "./policy-tool.js";
import {
  CLAUDE_CODE_INBOUND_SPEC,
  MCP_INBOUND_SPEC,
  classifyManduInspectResult,
  isPureSymbolicReadRendering,
  isStructuredTwinReadRendering,
  isStructuredTwinText,
  isOwnTextTwinText,
  claudeReadRenderingText,
  type TwinRenderingText,
  claudeReadWholeFileToken,
  wholeFileTwinTextToken,
  classifyStructuredTwinReadRendering,
  classifyPureSymbolicReadRendering,
  isReadHarnessNotice,
  isReadDedupNotice,
  classifyReadHarnessNotice,
  isHarnessTokenBudgetReminder,
  classifyHarnessTokenBudgetReminder,
  isCodexExecEnvelope,
  classifyCodexExecEnvelope,
  isHarnessInputValidationRejection,
  classifyHarnessInputValidationRejection,
  classifyExactContextEcho,
  classifyExecCleanUpgrade,
} from "./claude-code-inbound.js";
import type { ExecCleanVerdict } from "./exec-clean-verdicts.js";
import {
  selectSchemaBranch,
  lookupKey,
  type CategoryLookup,
} from "./resolve-schema.js";
import {
  isLiteralTrust,
  isKeySpec,
  isFieldMarker,
  isActionSpec,
  isItemsSchema,
  isObjectSchema,
  type SchemaNode,
  type FieldMarker,
} from "./schema-types.js";
import { createUrlTrustCategory } from "./trust-category.js";
import { destinationMatchesBindings } from "./host-bindings.js";
import {
  snapshotActivePolicy,
  type PolicyRuleSnapshot,
} from "./policy-snapshot.js";
import {
  decideFsPath,
  type FsPathDecisionRequest,
  type FsPathDecision,
} from "./fs-outbound.js";

/**
 * Minimal symbol-table view the egress gate needs: resolve a symbol name to its
 * provenance entry (or undefined if unknown). The arbiter passes a closure over
 * its SymbolMap; tests can pass an in-memory map. Kept structural so this module
 * does not import the symbol-table package (avoids a policy→symbol-table dep).
 */
export interface DesymSymbolEntry {
  /** The raw value (unused by the gate, present for parity with SymbolEntry). */
  value: string;
  /** Origin hint recorded at symbolization (URL/channel/dir). */
  origin: string | null;
  /** Obsolescence timestamp; non-null means the symbol is no longer active. */
  obsoleted_at: number | null;
  /** Confidentiality level (confidentiality.md §2). OPTIONAL so pre-axis
   * fixtures/mocks stay valid — absent parses to "public" (inert). The
   * arbiter's lookup returns full SymbolEntry rows, which carry it. */
  confidentiality?: string;
  /** Per-datum bound destinations (§2): host suffixes this datum may be
   * released to at egress. */
  bindings?: string[] | null;
  /** Integrity half of the 2×3 label (Plan 3): only the exact string
   * "trusted" counts; absent (pre-axis mocks) parses untrusted. */
  integrity?: string;
}

export type SymbolLookup = (symbol: string) => DesymSymbolEntry | undefined;

/** Inbound trust classification — mirrors Mandu policy/trust-category.ts `Trust`. */
export type Trust = "TRUSTED" | "UNTRUSTED";

/** Boundary at which data crosses into/out of the agent (plan §2 table). */
export type Boundary = "model_context" | "network" | "filesystem" | "shell";

/** Inbound classification request: a single field/value entering the boundary. */
export interface ClassifyRequest {
  /** Logical tool / source name (e.g. "web_fetch", "Read", "Bash"). */
  tool: string;
  /** Dotted field path within the result, if known (e.g. "results[0].title").
   * Absent → the whole result is one value classified against the tool's
   * top-level schema. */
  field?: string;
  /** The candidate value being classified. */
  value: string;
  /** Where this data is entering from. */
  boundary: Boundary;
  /** Origin hint (URL, channel id, dir path) for category/origin rules. When a
   * tool's schema keys a data field off `params.<x>` (e.g. web_fetch.text keyed
   * off params.url), the proxy passes the param value here as the origin. */
  origin?: string;
  /**
   * The SAME origin, spelled in the arbiter's own world — HumanView (Plan 9).
   *
   * A caller that runs an fs view map (the anthropic-proxy under fs-sync, which
   * is DEFAULT-ON for a git workspace) sees the AGENT's spelling on the request
   * wire: the agent executed the AgentView twin, so that is what it echoes back
   * in its `tool_use` args, and `origin` is derived from those args. But every
   * path policy the arbiter owns is keyed in HumanView — the catalog says
   * `~/.ssh`, the human labels `~/contracts`, and a derived label is minted on
   * the path the MODEL asked to write. Without this field they simply never
   * match, and a labeled file classifies `public`: the label is written and never
   * read.
   *
   * Used ONLY by the CONFIDENTIALITY derivation. The TRUST derivation keeps
   * seeing `origin`/`params` byte-identically — a view-map translation must never
   * be able to move a datum from UNTRUSTED to TRUSTED (that would be an integrity
   * regression smuggled in through a spelling change).
   */
  originHuman?: string;
  /** Optional extra params the tool was called with (e.g. { action: "read" }
   * for action-dispatched tools, or sibling fields). Merged with `origin` so
   * action selection + key lookups work. */
  params?: Record<string, unknown>;
  /**
   * The path-ish params, spelled in the arbiter's world — HumanView (Plan 9).
   * Same contract as `originHuman`, and needed for the same reason: the
   * confidentiality derivation takes the MAX over the origin AND the path-ish
   * params, so a params entry still spelled AgentView keeps hitting the CATALOG
   * (`.env`, `id_rsa` match on their BASENAME, which survives any prefix
   * translation) and that catalog hit OVERRIDES the human's label. Raise-only, so
   * it cannot leak — but it silently kills §6's DECLASSIFICATION: the human marks
   * `test/fixtures/.env` public and the file stays `no-model` anyway.
   *
   * Read ONLY by the confidentiality derivation. TRUST keeps seeing `params` —
   * `Read`'s trust is DIR-keyed off `params.file_path`, and a spelling change
   * must never be able to move a datum UNTRUSTED → TRUSTED.
   */
  paramsHuman?: Record<string, unknown>;
  /**
   * The directory a shell call whose params name no `workdir` runs in: its
   * session's directory, as the model-API proxy read it off the request FOR
   * CERTAIN (the openai-proxy: Codex's own `<environment_context>` names one
   * cwd and only one), in HumanView. Read ONLY by the confidentiality
   * derivation (`callWorkdir`, confidentiality.md §6); absent, a relative
   * token there keeps the catalog's verdict.
   */
  workdirDefault?: string;
  /**
   * The directory the session's agent resolves a RELATIVE path in a typed
   * path field against: the launch directory the launcher named the model
   * proxy (MANDU_AGENT_CWD), HumanView, sent by the anthropic-proxy for an
   * agent whose gate surface says `relativeBase: "launch"` (the same base its
   * fs gate resolves those fields against). Read ONLY by the confidentiality
   * derivation, and only for a tool the session's own gate surface lists in
   * `paths` with that base (`relativePathBase`; confidentiality.md §6);
   * absent, a relative path there keeps the catalog's verdict.
   */
  relativeBase?: string;
  /**
   * SET BY THE ARBITER ALONE (the server's classify handler drops any value a
   * caller sends): the directory the call's own shell started in, as the
   * kernel reported it to the guard at that shell's exec (`/proc/<pid>/cwd`,
   * read while the exec was suspended; `recordExecRoot.cwd` on the human
   * plane), for a call the call-root recorder bound to its shell
   * (`ProvenanceStore.callStartDir`). The directory a Claude Code `Bash`
   * call's relative path tokens are read in (`callWorkdir`,
   * confidentiality.md §6). Read ONLY by the confidentiality derivation;
   * absent, a relative token there keeps the catalog's verdict.
   */
  callStartDir?: string;
  /**
   * SET BY THE ARBITER ALONE (the server's classify handler drops any value a
   * caller sends; 2026-10-17, confidentiality.md §6, "The base follows the
   * shell"): for a call with no command whose typed path field holds a
   * RELATIVE path, each file the agent process itself opened in the call's
   * window whose path ends with that value (`token`), as the guard saw the
   * open in the kernel (`ProvenanceStore.callAgentOpens`). The agent
   * resolved the value against its own directory, which a `cd` in an earlier
   * `Bash` call or EnterWorktree moved; each `path` is read too, raise-only
   * (`labelForClassify`). Absent: the value keeps its other readings.
   */
  agentOpened?: Array<{ token: string; path: string }>;
  /**
   * MEASURED FACT from the model-API proxy (the only component holding the
   * conversation): the whole candidate span — `value` modulo one trailing
   * newline (claude-code-inbound.ts exactMatchCandidate) — appears
   * CONTIGUOUSLY in this same request's trusted, already-model-visible bytes
   * (system + user/assistant text + tool_use args; NEVER tool_result bodies —
   * rewrite-request.ts buildTrustedContextHaystack). Consumed only by the
   * exact-match upgrade (exec-routing.md §8.4 rung 1), which is
   * upgrade-only, tool-gated, and length-floored on the arbiter side. Absent
   * ⇒ the upgrade never fires (fail-closed); an older caller simply never
   * sends it.
   */
  verbatimInTrustedContext?: boolean;
  /**
   * The originating tool_use id of the tool_result being classified — the
   * correlation key back to per-invocation runtime state the arbiter itself
   * recorded. Consumed today by the exec CLEAN-verdict upgrade
   * (exec-routing.md §8.4 rung 2: ExecCleanVerdictStore, hash-bound).
   * Absent ⇒ no correlation-keyed rule fires (fail-closed).
   */
  callId?: string;
  /**
   * The tool call whose recorded process tree the clean-tree release reads
   * (docs/design/confidentiality/clean-tree-release.md, rule R3), for a
   * caller that names no `callId` (the openai-proxy: its classify reads a
   * relative path off the call's `workdir`, not the guard's start directory,
   * which `callId` would add). Read by the arbiter's classify op alone; the
   * policy ignores it. Absent with `callId` absent ⇒ no offer.
   */
  treeCallId?: string;
  /**
   * Session identity for SESSION-KEYED spec resolution (agent-e2e-harness.md
   * §7.1): the same key the proxy threads into `symbolize` (the launcher's
   * MANDU_SESSION_KEY / scopeId). When the session was bound to a spec via
   * the `setSessionSpec` IPC op, classification resolves tool names against
   * THAT agent's inbound spec; absent or unbound falls back to the
   * process-global boot spec — older callers behave byte-identically. Fallback
   * degrades toward over-symbolization: a non-Claude session on the default
   * global spec misses every tool name and classifies fail-closed UNTRUSTED.
   */
  sessionKey?: string;
}

export interface ClassifyResult {
  trust: Trust;
  /** Which category drove the decision, if any (URL/CHANNEL/DIR). */
  category: string | null;
  /** Human-readable reason — useful for the audit oracle. */
  reason: string;
  /** Confidentiality of the classified datum (confidentiality.md §2), derived
   * from file provenance (origin/params paths) by the engine wrapper. ABSENT
   * while the confidentiality axis is OFF — consumers treat absent as
   * "public". Never set per trust branch; one derivation site only. */
  confidentiality?: ConfidentialityLevel;
  /** Bound destinations the label grants (§2) — the standing release rules for
   * this datum. Carried from the user label (Plan 6) or a catalog rule. ABSENT
   * while the axis is OFF, and absent when the label grants none. */
  bindings?: string[];
  /** The tokens of the call's origin hint and input (its path fields, its
   *  command text) that name a secret path, as written there, when the level
   *  is secret
   *  (`labelForClassify`'s `paths`). The model proxy names them in the
   *  path-derived note (confidentiality.md §7.1). ABSENT when none. */
  namedPaths?: string[];
  /** The absolute files (HumanView) every secret reading of the call's
   *  origin and input resolves to (`labelForClassify`'s `files`), when the
   *  level is this path rule's and every reading could be placed; ABSENT
   *  otherwise. Arbiter-side only: the classify op keeps it in its record of
   *  the call (plan 15 §13.12) and strips it from the wire answer. */
  namedFiles?: string[];
  /** With `namedFiles`: every file the call's plain path tokens name,
   *  whatever its label (`labelForClassify`'s `placed`); a path row may stop
   *  fingerprinting a line only when one of these files holds it verbatim
   *  (plan 15 §13.12). Arbiter-side only, like `namedFiles`. */
  placedFiles?: string[];
  /** With `namedFiles`, for a command that opens with a `cd` to one literal
   *  folder (`dir`): the same two lists placed where the command started,
   *  for when that `cd` failed (plan 15 §13.12, "A cd that fails";
   *  `labelForClassify`'s `ifCdFailed`). The arbiter uses them in place of
   *  `namedFiles` / `placedFiles` only when `dir` is not a directory when
   *  the mark is learned. Arbiter-side only, like `namedFiles`. */
  ifCdFailed?: { dir: string; namedFiles: string[]; placedFiles: string[] };
  /** Set by the arbiter's classify op, never by the policy: `value-backstop`
   *  when the level is the value backstop's raise of a verdict the policy
   *  called public (plan 15 §13.11, "What a raised row registers"). ABSENT
   *  otherwise. */
  raisedBy?: "value-backstop";
  /** Set by the arbiter's classify op beside `raisedBy`, never by the
   *  policy: the value-only release it offers
   *  (docs/design/confidentiality/backstop-value-only.md). `text` is the
   *  classified value with each `spans` entry ([start, end) of the value,
   *  sorted, disjoint) replaced by its `symbol`, verified to hold no
   *  registered value in any form the arbiter looks for. An OFFER: the
   *  verdict's level stays the raise, and a consumer that does not know this
   *  field, or whose own evidence says the call read a secret, masks the
   *  result whole. ABSENT when the arbiter cannot prove such a release. */
  valueOnly?: { text: string; spans: Array<{ start: number; end: number; symbol: string }> };
  /** Set by the arbiter's classify op beside a path-derived verdict, never
   *  by the policy: the clean-tree release it offers
   *  (docs/design/confidentiality/clean-tree-release.md). The same shape as
   *  `valueOnly`, but `spans` may be empty (then `text` is the value as it
   *  is). An OFFER: the verdict's level stays secret, and a consumer that
   *  does not know this field, or whose own evidence says the call read a
   *  secret, masks the result whole. ABSENT when the arbiter cannot prove
   *  such a release. */
  pathRelease?: { text: string; spans: Array<{ start: number; end: number; symbol: string }>; listing?: { operands: string[]; part: "first" | "last" } };
  /** Set by the arbiter's classify op beside a secret verdict's
   *  `namedPaths`, never by the policy (named-twins.ts, confidentiality.md
   *  §7.1): for each named token whose secret files all have a twin of one
   *  kind, that kind, so the path-derived note can say how to read the file
   *  itself. Explains only: never lowers or raises the level. ABSENT when
   *  no token has one. */
  namedTwins?: NamedTwin[];
}

/** Where a symbol sits in an outgoing network request (plan 10 §11.13.1,
 *  "The Authorization header only"): `authorization` = inside the request's
 *  own credential header (the net-proxy: the `Authorization` value, the
 *  decoded pair of `Basic` included, never `Proxy-Authorization`; the model
 *  proxy: the provider auth header it fills, `x-api-key` or `Authorization:
 *  Bearer`); `url` = the request URL or its host; `header` = any other
 *  header; `body` = the body. */
export type RequestPosition = "authorization" | "url" | "header" | "body";

/** Every {@link RequestPosition}, in the order the gate names them. */
export const REQUEST_POSITIONS: readonly RequestPosition[] = ["authorization", "url", "header", "body"];

/** Egress desymbolization request: a symbol about to be resolved to raw value. */
export interface DesymbolizationRequest {
  /** The symbol name being considered for resolution. */
  symbol: string;
  /** Where the resolved value would flow to. */
  boundary: Boundary;
  /** Destination hint (URL host, argv position, file path). For `network`
   * egress this is the request URL/host — the gate checks it against the URL
   * trust category (an untrusted destination requires approval). */
  destination?: string;
  /** True if the resolved value would be used as a command/code (exec). The
   * data-usage policy treats an untrusted symbol in command/code position as
   * always requiring human approval. */
  asCommand?: boolean;
  /** Requesting session key — attribution ONLY, never a decision input (the
   * pure gate ignores it). Rides to the approval-queue row
   * (EgressApproval.sessions) via the server wrap. */
  sessionKey?: string;
  /** For `network`: the scheme the value would travel in, when the caller
   * knows it (the net-proxy: `http` on its plain leg, `https` on its
   * TLS-inspected leg). A wire-twin credential declared for https is never
   * put back without `https` here (plan 10 §11.13.1, 2026-10-03; absent ⇒
   * refused, fail-closed). */
  scheme?: "http" | "https";
  /** For `network`: EVERY place in the request the symbol sits, when the
   * caller knows it (the net-proxy reads the whole request; the model
   * proxy's key put-back writes one auth header). A credential whose release
   * at this destination rests only on an automatic wire binding (the wire
   * twin's registry or index host, an auth grant: current-bindings.ts
   * `releaseRestsOnWireGrant`) is put back only when every position is
   * `authorization`; absent, empty or any other position ⇒ refused, with
   * `asCommand` set or not (`wirePositionRefusal`, plan 10 §11.13.1,
   * 2026-10-09, fail-closed). */
  positions?: RequestPosition[];
  /** For `network`: this ask is a PRE-CHECK, and the release (if any) is
   * judged again where the value is put back (the model proxy's network gate
   * at the tool_use; the net-proxy releases and asks again on the wire). A
   * human's *Allow once* is then read without being spent, so the real send
   * is the ask that spends it; a *once* denial is spent here, since the
   * pre-check enacts it and no send follows (arbiter-human-plane.md §10.3).
   * Honored only from an attested channel; it never grants anything the
   * same ask without it would refuse. */
  preflight?: boolean;
  /** For `network`: one id per request the caller judges (the net-proxy:
   * one per HTTP request's gate run, held or not; egress-hold.md "One card
   * per file"). A human's *once* answer is spent by the first ask that
   * carries it and then holds for the other asks of THAT request only (the
   * other placeholders of the same file, whose card is one), never for a
   * later request. Absent: spent by the first ask, as before. Honored only
   * from an attested channel (an ask elsewhere spends nothing); never a
   * grant on its own. */
  requestId?: string;
  /** For `network`: every placeholder the same request carries (the
   * net-proxy's whole request; at most REQUEST_SYMBOLS_MAX are read). Two or
   * more placeholders of one registered file in it ask on ONE card, the
   * file's (egress-hold.md "One card per file"); a lone one keeps its own
   * card. Attribution of the card only: the decision never reads it. */
  requestSymbols?: string[];
}

export type DesymbolizationDecision =
  | {
      allow: true; reason: string; ruleRef?: RuleRef;
      /** A pre-check (`preflight`) of a pair the human answered "Send
       * without it" (confidentiality.md §4 "Send without it"): the call may go on to the send,
       * where the net-proxy's ask spends the answer; nothing is released.
       * Stamped by the server wrap only. */
      strip?: true;
    }
  | {
      allow: false;
      requiresApproval: boolean;
      reason: string;
      ruleRef?: RuleRef;
      /** "Send without it" (confidentiality.md §4): the human's one-shot
       * answer, spent by this decision. The value is NOT released; the
       * net-proxy forwards THIS request with a neutral marker where the
       * symbol is. A caller that does not know the flag reads a denial
       * (fail-closed). Stamped by the server wrap only. */
      strip?: true;
      /** The approval-queue entry this deny created/bumped (`egr-<n>`), stamped
       * by the server wrap when requiresApproval queued a pending row — the
       * event-side join back to the Pending tab (policy-surface.md §9.5).
       * Absent from the pure gate. */
      approvalId?: string;
    };

/**
 * The policy surface the arbiter exposes. Track A and the OS interceptors call
 * these; the lifted Mandu engine implements `classify` once lifted (now).
 */
export interface PolicyEngine {
  /** Data trust policy: should this inbound value be symbolized? */
  classify(req: ClassifyRequest): ClassifyResult;
  /** The confidentiality level `classify`'s path rules give `req` (its
   *  origin and input, both HOMEs, an unmapped tool's every string) when the
   *  labels are read through `lookup` instead of the engine's own: the
   *  clean-tree release's counterfactual reading
   *  (docs/design/confidentiality/clean-tree-release.md, rule R4). Decides
   *  nothing on its own. Optional: an engine without it gives no release. */
  pathLevelWith?(req: ClassifyRequest, lookup: LabelLookup): ConfidentialityLevel;
  /** The directory `classify`'s path rules read a call's relative paths in
   *  (`callWorkdir`: the guard's start directory, else a `workdir` the
   *  session's agent honours for that tool, else the session's default), or
   *  undefined. The clean-tree release's start directory (R4). Optional. */
  callWorkdirOf?(req: ClassifyRequest): string | undefined;
  /** Data usage policy: may this symbol be desymbolized on egress? */
  desymbolizationDecision(req: DesymbolizationRequest): DesymbolizationDecision;
  /** The SAME gate over a caller-supplied symbol lookup — the Test-a-flow
   * tester's probe (policy-surface.md §5 "Tester ≡ gates"): a
   * synthetic entry decided by the real branches, nothing recorded. Optional:
   * an injected/stub engine may lack it (the tester then reports so). */
  desymbolizationDecisionWith?(req: DesymbolizationRequest, lookup: SymbolLookup): DesymbolizationDecision;
  /** Data usage policy, filesystem: may this tool touch this absolute path?
   * The sensitive-path gate (fs-outbound.ts; fs-sync.md §1.4.1). */
  fsPathDecision(req: FsPathDecisionRequest): FsPathDecision;
  /** Observability: the active inbound/outbound/origin rules, serialized for
   * the dashboard's per-tool-call policy modal. Decides nothing; mirrors the
   * specs classify()/desymbolizationDecision() enforce. */
  policySnapshot(): PolicyRuleSnapshot;
}

// ─────────────────────────────────────────────────────────────────────────────
// Field-path navigation over a SchemaNode.
//
// The IPC `classify` op is per-value (tool + field + value), whereas the lifted
// `walkSchema` is whole-result. To classify a single span we navigate the tool's
// schema to the marker at `field` (a dotted path with `[i]` array segments),
// then resolve that marker. A field that the schema does not describe is
// deny-by-default UNTRUSTED (mirrors walkSchema's unknown-key semantics).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Where a classify request's relative TYPED path fields are read
 * (2026-10-09, confidentiality.md §6): the `relativeBase` the model proxy
 * sent, but only when the SESSION'S OWN gate surface (the arbiter's table,
 * keyed on the same session the trust spec is) says its agent resolves a
 * relative path against the launch directory (`relativeBase: "launch"`) and
 * lists the call's tool in `paths`; then for that tool's path fields only.
 * Claude Code's surface names no such base (its relative paths follow the
 * shell's `cd`), nor does the union a session with no spec falls back to,
 * so a proxy's base is ignored there. Pure but for the session-spec lookup
 * (`specs`: the engine's registry, its arbiter's own).
 */
export function relativePathBase(
  req: Pick<ClassifyRequest, "tool" | "relativeBase" | "sessionKey">,
  specs: SessionSpecLookup = processSessionSpecs,
): TypedPathBase | undefined {
  if (typeof req.relativeBase !== "string" || typeof req.tool !== "string") return undefined;
  const surface = gateSurfaceFor(req.sessionKey, specs);
  if (surface.relativeBase !== "launch") return undefined;
  if (!Object.prototype.hasOwnProperty.call(surface.paths, req.tool)) return undefined;
  return { dir: req.relativeBase, fields: surface.paths[req.tool]!.fields };
}

/**
 * The tools whose `workdir` the SESSION'S agent honours (2026-10-11,
 * confidentiality.md §6): the `workdir` table of the session's own gate
 * surface, keyed on the same session the trust spec is. Goose's names none
 * (its `shell` has no `workdir`, though Codex's tool has the name); a
 * session with no table of its own gets the union's, which believes only
 * what every agent honours. Pure but for the session-spec lookup.
 */
export function sessionWorkdirTools(
  req: Pick<ClassifyRequest, "sessionKey">,
  specs: SessionSpecLookup = processSessionSpecs,
): WorkdirTools {
  return gateSurfaceFor(req.sessionKey, specs).workdir ?? {};
}

/** Split a dotted path into segments, treating `a.b[0].c` → ["a","b","[0]","c"]. */
function splitFieldPath(field: string): string[] {
  const segs: string[] = [];
  for (const part of field.split(".")) {
    if (part === "") continue;
    // Pull out trailing [i] index segments.
    const m = part.match(/^([^[]*)((?:\[\d+\])*)$/);
    if (!m) { segs.push(part); continue; }
    if (m[1]) segs.push(m[1]);
    const idx = m[2];
    if (idx) {
      for (const i of idx.matchAll(/\[(\d+)\]/g)) segs.push(`[${i[1]}]`);
    }
  }
  return segs;
}

/** Navigate to the schema node + enclosing scope for a dotted field path.
 * Returns null if the path leaves the described schema (→ deny-by-default). */
function navigateToMarker(
  schema: SchemaNode,
  segments: string[],
): { node: SchemaNode } | null {
  let node: SchemaNode = schema;
  for (const seg of segments) {
    if (seg.startsWith("[") && seg.endsWith("]")) {
      // Array index — descend through __items.
      if (isItemsSchema(node)) { node = node.__items; continue; }
      return null;
    }
    if (isObjectSchema(node)) {
      const child = (node as Record<string, SchemaNode>)[seg];
      if (child === undefined) return null; // field not in schema
      node = child;
      continue;
    }
    // Tried to descend into a leaf/array with an object key → off-schema.
    return null;
  }
  return { node };
}

function trustFromMarker(
  marker: FieldMarker,
  origin: string | undefined,
  params: Record<string, unknown>,
  categories: CategoryLookup,
): ClassifyResult {
  if (isLiteralTrust(marker)) {
    return {
      trust: marker,
      category: null,
      reason: `schema rule: literal ${marker}`,
    };
  }
  if (isKeySpec(marker)) {
    return {
      trust: "TRUSTED",
      category: marker.category,
      reason: `schema rule: ${marker.category} key field (raw, always TRUSTED)`,
    };
  }
  // DataSpec — resolve the key against its category.
  // The key value comes from params (params.<x>), a sibling in `params`, or the
  // explicit `origin` hint (which the proxy fills in for params-keyed data).
  let keyValue = lookupKey(marker.keyField, params, params);
  if (keyValue == null && origin != null) keyValue = origin;
  const category = categories.get(marker.category);
  if (!category) {
    return {
      trust: "UNTRUSTED",
      category: marker.category,
      reason: `fail-closed: category '${marker.category}' not registered`,
    };
  }
  const trust = category.classify(keyValue);
  return {
    trust,
    category: marker.category,
    reason: `origin rule: ${marker.category}.classify(${keyValue ?? "∅"}) → ${trust}`,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine-backed policy (the lifted data-trust path).
// ─────────────────────────────────────────────────────────────────────────────

export interface EngineBackedPolicyOptions {
  /** Path to a YAML policy file (origin lists + tool overrides). Optional —
   * without it the engine runs on the built-in TOOL_INBOUND_SPEC + intrinsic
   * category defaults (URL allowlist-empty, CHANNEL/DIR blocklist-empty). */
  policyPath?: string;
  /** Base path for resolving relative policy paths / DIR entries. */
  basePath?: string;
  /** In-memory policy override (bypasses file loading; used by tests). Pass
   * `null` to force "no policy file" without touching disk. */
  policyFileOverride?: PolicyFileConfig | null;
  /** Optional logger; defaults to a no-op (arbiter logs separately). */
  log?: { info(m: string): void; warn(m: string): void };
  /**
   * Resolve a symbol name to its provenance entry, for the egress gate. When
   * omitted, the gate treats EVERY symbol as unknown → fail-closed (always
   * requiresApproval). The arbiter wires this to its SymbolMap so the gate can
   * tell an active symbol from an unknown/obsolete one.
   */
  symbolLookup?: SymbolLookup;
  /**
   * EXACT-name allocation test (no candidate walk), for the read-twin rule
   * (claude-code-inbound.ts isPureSymbolicReadRendering): a Read rendering is
   * forwarded raw only when every token on it is a name the arbiter minted.
   * The lenient `symbolLookup` walk would accept an invented field tail, which
   * is exactly the channel that rule must not open. Omitted ⇒ the rule never
   * fires (fail-closed — the result is symbolized as before).
   */
  symbolAllocated?: (symbol: string) => boolean;
  /**
   * The STRUCTURED twin text the registry minted for a path (plan 10 §2.4,
   * secret-registry structuredTwinFor), for the structured read-twin rule: a
   * Read rendering that is a substring of it carries no secret byte and is
   * forwarded raw (keys and field tokens). Omitted ⇒ the rule never fires.
   */
  twinRendering?: (path: string) => TwinRenderingText | null;
  /**
   * The WHOLE-FILE twin the guard serves for a path now (plan 10 §11.8, "A
   * document's own twin", secret-registry wholeFileTwinFor): the base token
   * and the file's final terminator, for the read leg: a built-in read whose
   * rendering is exactly that twin carries no secret byte and is forwarded
   * raw (the document's own token). Omitted ⇒ the rule never fires.
   */
  wholeFileTwin?: (path: string) => { token: string; terminator: string } | null;
  /**
   * The OWN-TEXT twin the guard serves for a path now (plan 10 §11.13, "A
   * config with no secret", secret-registry ownTextTwinFor): the text of a
   * registered exhaustive-shape file whose extraction found no secret value,
   * for the read leg: a built-in read whose rendering is a piece of it
   * carries no secret byte and is forwarded as it is. Omitted ⇒ the rule
   * never fires.
   */
  ownTextTwin?: (path: string) => string | null;
  /**
   * The HOME the launcher of a session recorded on the human plane (plan 10
   * §11.13, the arbiter's `beginLaunch` record), for the confidentiality
   * derivation: the catalog's `~` places of it count as well as the
   * arbiter's own, the stricter deciding. Omitted, or null for a session ⇒
   * the arbiter's HOME alone, as before.
   */
  sessionHome?: (sessionKey: string | undefined) => string | null;
  /**
   * Resolve a filesystem path to its USER label (Plan 6, path-labels.ts), for
   * the confidentiality derivation. Injected rather than imported so the
   * derivation stays a pure function of its inputs (tests pass a map; the
   * arbiter passes the live store). Omitted ⇒ the default-secret catalog alone
   * decides, exactly as before Plan 6.
   */
  labelLookup?: LabelLookup;
  /** The confidentiality-axis kill switch (confidentiality.md §11). Defaults
   * from MANDU_CONFIDENTIALITY (default OFF). OFF ⇒ classify results carry
   * no confidentiality field — byte-identical to the integrity-only system.
   * The arbiter passes its own switch value so server and engine agree. */
  confidentiality?: boolean;
  /** The integrity-axis switch (integrity-flag.ts; confidentiality.md §11's
   * two-axis dual). Defaults from MANDU_INTEGRITY (default ON). OFF ⇒
   * classify() returns TRUSTED for every field — no untrusted symbol is ever
   * minted, so every downstream integrity gate collapses — while the
   * confidentiality derivation (level/bindings) is untouched. The arbiter
   * passes its own switch value so server and engine agree. */
  integrity?: boolean;
  /**
   * Resolve a tool_use callId to its recorded exec CLEAN verdict (the
   * ExecCleanVerdictStore the arbiter owns), for the rung-2 upgrade
   * (exec-routing.md §8.4–§5). Injected like symbolLookup/labelLookup so
   * the decision logic stays a pure function of its inputs. Omitted ⇒ the
   * clean-verdict upgrade never fires (fail-closed) — exactly today's
   * behavior for every caller that does not wire a store.
   */
  execCleanLookup?: (callId: string) => ExecCleanVerdict | undefined;
  /**
   * The session→spec bindings classify resolves a request's `sessionKey`
   * against (tool-inbound.ts SessionSpecs): an ArbiterServer passes ITS OWN
   * registry, the one its `setSessionSpec` binds in, and the same object to
   * every engine it rebuilds, so a policy reload keeps the bindings.
   * Omitted ⇒ the process registry (direct callers: unit tests, embedders
   * of the bare engine).
   */
  sessionSpecs?: SessionSpecLookup;
}

/**
 * Build the engine-backed policy. `classify()` runs the lifted data-trust
 * engine: schema rule → origin rule → fail-closed UNTRUSTED default.
 * `desymbolizationDecision()` runs the lifted data-USAGE / egress gate (see
 * `decideDesymbolization`).
 */
export function createEngineBackedPolicy(
  opts: EngineBackedPolicyOptions = {},
): PolicyEngine {
  const log = opts.log ?? { info: () => {}, warn: () => {} };
  const basePath = opts.basePath ?? process.cwd();
  const sessionSpecs = opts.sessionSpecs ?? processSessionSpecs;
  // The document is loaded ONCE and shared by the origin-classifier registry
  // and the compiled law (policy-surface.md §2.2): `compilePolicy`
  // applies the tool/command overrides to COPIES of the built-in tables and
  // the result is swapped in atomically — no module table is ever mutated.
  const document: PolicyFileConfig | null =
    opts.policyFileOverride !== undefined ? opts.policyFileOverride : loadPolicyFile(opts.policyPath, basePath, log);
  // `@list` references in the origin lists are expanded before the classifier
  // registry sees them (compilePolicy expands the same way internally).
  const categories: TrustCategoryEngine = createPolicyEngine(opts.policyPath, basePath, log, expandListsInDocument(document));
  swapCurrentPolicy(
    compilePolicy({
      specId: getActiveInboundSpecId(),
      document,
      lawSource: opts.policyFileOverride !== undefined ? { kind: "custom" } : describeLawSource(opts.policyPath, basePath),
      log,
    }),
  );
  const symbolLookup = opts.symbolLookup;
  const symbolAllocated = opts.symbolAllocated;
  const twinRendering = opts.twinRendering;
  /** The built-in read a request is, for the read-twin rules (the structured
   *  twin below, and a document's whole-file twin): the path it read and,
   *  for OpenClaw and OpenCode, its text with the agent's frame stripped
   *  (Claude Code's gutter is left to each rule's own parser). The
   *  path is the HumanView spelling when the caller supplied one (the registry
   *  is keyed in HumanView), else the raw param/origin.
   *
   *  OpenClaw's and OpenCode's `read` get the same rule (plan 10 §11.8), each
   *  with its own rendering stripped by a parser pinned to its published
   *  source (openclaw-inbound.ts / opencode-inbound.ts) and then the shared
   *  content test (isStructuredTwinText). Keyed by SPEC IDENTITY, like the
   *  Claude branch in classifyTrust: the tool resolves to exactly that
   *  agent's `read` entry, so a YAML override (a different object) or another
   *  agent's session never takes the branch. */
  const builtinRead = (req: ClassifyRequest):
    | { agent: "claude-code"; path: string }
    | { agent: "openclaw" | "opencode"; path: string; text: string | null }
    | null => {
    if (req.field) return null;
    const params = (req.paramsHuman ?? req.params) as Record<string, unknown> | undefined;
    const param = (...keys: string[]): string | undefined => {
      for (const k of keys) if (params && typeof params[k] === "string") return params[k] as string;
      return undefined;
    };
    /** The registry's (absolute) spelling of the path a `read` named: the
     *  path field as given when absolute; a RELATIVE one only where the
     *  agent itself reads it, its launch directory (`relativePathBase`: the
     *  session's own gate surface says `relativeBase: "launch"` and lists
     *  this field), resolved as the label lookup resolves it
     *  (`resolveTypedPathOrigin`); else the origin hint when absolute.
     *  2026-10-11, the OpenClaw tour walk: OpenClaw's model writes
     *  `read {path: ".env"}`, which never matched the registry, so the
     *  structured twin it was served went to the model as ONE whole-file
     *  placeholder and no key could be used on its own. A wrong resolution
     *  only fails the content test below (the mask stands). */
    const readPath = (...keys: string[]): string | undefined => {
      for (const k of keys) {
        const v = params && typeof params[k] === "string" ? (params[k] as string) : undefined;
        if (v === undefined) continue;
        if (v.startsWith("/")) return v;
        const base = relativePathBase(req, sessionSpecs);
        return base !== undefined && base.fields.includes(k) ? resolveTypedPathOrigin(v, base.dir) : undefined;
      }
      const o = req.originHuman ?? req.origin;
      return o && o.startsWith("/") ? o : undefined;
    };
    if (req.tool === "Read") {
      const path = param("file_path") ?? req.originHuman ?? req.origin;
      if (!path || !path.startsWith("/")) return null;
      return { agent: "claude-code", path };
    }
    if (req.tool !== "read") return null;
    const spec = getToolInboundSpec(req.tool, req.sessionKey, sessionSpecs);
    if (spec === OPENCLAW_AGENT_INBOUND_SPEC.read) {
      const path = readPath("path", "file_path");
      if (!path) return null;
      return { agent: "openclaw", path, text: openclawReadRenderingText(req.value) };
    }
    if (spec === OPENCODE_INBOUND_SPEC.read) {
      // `filePath` on OpenCode 1, `path` on OpenCode 2 (2.0.23).
      const path = readPath("filePath", "path");
      if (!path) return null;
      // The `<path>` header OpenCode 1 prints is the AgentView spelling the
      // agent resolved, OpenCode 2's `Read file` header the path as called;
      // accept either only as one the call itself named.
      const rawOf = (k: string): string | undefined =>
        req.params && typeof req.params[k] === "string" ? (req.params[k] as string) : undefined;
      const raw = rawOf("filePath") ?? rawOf("path");
      const spellings = [path, raw, req.origin, req.originHuman].filter((p): p is string => typeof p === "string");
      return { agent: "opencode", path, text: opencodeReadRenderingText(req.value, spellings) };
    }
    return null;
  };
  const isStructuredTwinRead = (req: ClassifyRequest): boolean => {
    if (!twinRendering) return false;
    const r = builtinRead(req);
    if (r === null) return false;
    if (r.agent === "claude-code") return isStructuredTwinReadRendering(req.value, twinRendering(r.path), symbolAllocated);
    return r.text !== null && isStructuredTwinText(r.text, twinRendering(r.path), symbolAllocated);
  };
  const wholeFileTwin = opts.wholeFileTwin;
  /** The read leg of "A document's own twin" (plan 10 §11.8): a built-in
   *  read of a labelled document whose rendering is EXACTLY the whole-file
   *  twin the guard serves for that path now, the path's newest registered
   *  base token, alone (Claude Code's `Read`, under its own spec entry: line
   *  1 and at most the harness's empty row after the file's own terminator,
   *  claudeReadWholeFileToken; OpenClaw's and OpenCode's `read`: the token as
   *  the read's text, their frames stripped by the pinned parsers above).
   *  The token must be that path's, so a token of another file, an older
   *  registration, a proxy's Read row or a field token never passes. */
  const isWholeFileTwinRead = (req: ClassifyRequest): boolean => {
    if (!wholeFileTwin) return false;
    const r = builtinRead(req);
    if (r === null) return false;
    const twin = wholeFileTwin(r.path);
    if (twin === null) return false;
    const token = r.agent === "claude-code"
      ? (getToolInboundSpec(req.tool, req.sessionKey, sessionSpecs) === CLAUDE_CODE_INBOUND_SPEC.Read ? claudeReadWholeFileToken(req.value, twin.terminator) : null)
      : wholeFileTwinTextToken(r.text);
    return token !== null && token === twin.token;
  };
  const ownTextTwin = opts.ownTextTwin;
  /** The read leg of "A config with no secret" (plan 10 §11.13): a
   *  built-in read of a registered file whose twin is its OWN TEXT, whose
   *  rendering (Claude Code's `Read` under its own spec entry, its gutters
   *  stripped; OpenClaw's and OpenCode's `read`, their frames stripped by
   *  the pinned parsers above) is one piece of that text. */
  const isOwnTextTwinRead = (req: ClassifyRequest): boolean => {
    if (!ownTextTwin) return false;
    const r = builtinRead(req);
    if (r === null) return false;
    const text = r.agent === "claude-code"
      ? (getToolInboundSpec(req.tool, req.sessionKey, sessionSpecs) === CLAUDE_CODE_INBOUND_SPEC.Read ? claudeReadRenderingText(req.value) : null)
      : r.text;
    if (text === null || text === undefined) return false;
    return isOwnTextTwinText(text, ownTextTwin(r.path));
  };
  /** Whose write notice a result may be (own-write-notice.ts), by SPEC
   *  IDENTITY like the read-twin rule above: the tool resolves to exactly
   *  that agent's built-in write entry, so a policy.yaml tool rule (another
   *  object) or another agent's session never takes the release. */
  const ownWriteNoticeAgent = (req: ClassifyRequest): OwnWriteNoticeAgent | null => {
    if (req.tool !== "Write" && req.tool !== "write") return null;
    const spec = getToolInboundSpec(req.tool, req.sessionKey, sessionSpecs);
    if (spec === undefined) return null;
    if (spec === CLAUDE_CODE_INBOUND_SPEC.Write) return "claude-code";
    if (spec === OPENCODE_INBOUND_SPEC.write) return "opencode";
    if (spec === GOOSE_INBOUND_SPEC.write) return "goose";
    if (spec === OPENCLAW_AGENT_INBOUND_SPEC.write) return "openclaw";
    return null;
  };
  const confidentialityEnabled =
    opts.confidentiality ?? resolveConfidentialityEnabled();
  const integrityEnabled = opts.integrity ?? resolveIntegrityEnabled();

  // The lifted data-TRUST classification, unchanged. Wrapped below so the
  // confidentiality axis is derived at ONE site (never per trust branch).
  function classifyTrust(req: ClassifyRequest): ClassifyResult {
      // Harness token-budget reminder (claude-code-inbound.ts — rationale and
      // the anchored digits-only grammar live there): tool-AGNOSTIC because the
      // agent runtime appends it to EVERY tool's result, whole-result only so a
      // field-addressed walk keeps its schema semantics. Checked before the
      // spec lookup on purpose — the shape is trusted even for tools with no
      // inbound spec (the fail-closed default would otherwise mint a decoy
      // symbol next to the real result in every split tool_result).
      if (!req.field && isHarnessTokenBudgetReminder(req.value)) {
        return classifyHarnessTokenBudgetReminder();
      }

      // Codex exec envelope (claude-code-inbound.ts — rationale + grammar):
      // the openai-proxy splits codex's leading exec_command output header
      // off and asks about it alone; digits/hex-only, whole-result only.
      if (!req.field && isCodexExecEnvelope(req.value)) {
        return classifyCodexExecEnvelope();
      }

      // Harness input-validation rejection (claude-code-inbound.ts — rationale
      // and the anchored identifier-locked grammar live there): the harness
      // refused the call BEFORE dispatch, so the message is harness-authored
      // from the model's own input + the tool's static schema. Tool-AGNOSTIC
      // (any tool's call can be rejected — including unmapped ones, so this
      // too runs before the spec lookup) and whole-result only. Symbolizing it
      // blinds the model to WHY its call failed (live: opus retry-looped on a
      // hallucinated Bash `env` parameter, seeing only opaque tokens).
      if (!req.field && isHarnessInputValidationRejection(req.value, req.tool, req.params)) {
        return classifyHarnessInputValidationRejection();
      }

      const spec = getToolInboundSpec(req.tool, req.sessionKey, sessionSpecs);
      if (!spec) {
        // Unknown tool (any name outside the active spec map — including new
        // Claude Code harness tools that have not been deliberately mapped in
        // claude-code-inbound.ts) → fail closed. This is the safe default:
        // over-symbolize.
        return {
          trust: "UNTRUSTED",
          category: null,
          reason: `fail-closed: no inbound spec for tool '${req.tool}' → symbolize`,
        };
      }

      // Mandu-internal U-LLM inspect tool (interceptors/inspect-mcp): refine
      // the generic mcp__* fallback with the HYBRID exact-name + pure-symbolic-
      // shape rule (claude-code-inbound.ts, classifyManduInspectResult — the
      // audit of every string that can reach that tool result lives there).
      // `spec === MCP_INBOUND_SPEC` encodes both gates at once: the prefix
      // fallback only fires under the claude-code spec, and an explicit exact-
      // name entry (e.g. a YAML tool override) resolves to a DIFFERENT object
      // and therefore still wins over this refinement. Whole-result only: a
      // field-addressed request falls through to the generic fail-closed walk.
      if (spec === MCP_INBOUND_SPEC && isManduInspectTool(req.tool) && !req.field) {
        return classifyManduInspectResult(req.value);
      }
      // Mandu policy tools (interceptors/policy-mcp): exact name + a
      // token-only envelope (policy-tool.ts has the audit). Same gates and
      // whole-result-only scope as the inspect refinement above.
      if (spec === MCP_INBOUND_SPEC && isManduPolicyTool(req.tool) && !req.field) {
        return classifyManduPolicyResult(req.tool, req.value);
      }

      // Claude Code's Read (claude-code-inbound.ts — rationale and grammars
      // live there). `spec === CLAUDE_CODE_INBOUND_SPEC.Read` encodes both
      // gates, like the inspect refinement above: the tool is exactly `Read`
      // under the claude-code spec, and an explicit override (a YAML tool
      // rule) resolves to a different object and still wins. Whole-result
      // only. Two shapes pass raw; every other Read result keeps the
      // fail-closed whole-result rule below.
      //   * a fixed harness NOTICE returned instead of content (file
      //     unchanged / empty / shorter than the offset) — no file byte in it;
      //   * the line-numbered rendering of a whole-file symbol TWIN — nothing
      //     but digits and names this arbiter minted (exact allocation test).
      if (spec === CLAUDE_CODE_INBOUND_SPEC.Read && !req.field) {
        if (isReadHarnessNotice(req.value, req.tool, req.params)) {
          return classifyReadHarnessNotice();
        }
        if (isPureSymbolicReadRendering(req.value, symbolAllocated)) {
          return classifyPureSymbolicReadRendering();
        }
        if (isStructuredTwinRead(req)) {
          return classifyStructuredTwinReadRendering();
        }
      }
      // OpenClaw's and OpenCode's `read`: the structured read-twin rule only
      // (plan 10 §11.8), under the same spec-identity gate. Neither agent's
      // read has the pure-symbolic or harness-notice shapes pinned here.
      if ((spec === OPENCLAW_AGENT_INBOUND_SPEC.read || spec === OPENCODE_INBOUND_SPEC.read) && !req.field) {
        if (isStructuredTwinRead(req)) {
          return classifyStructuredTwinReadRendering();
        }
      }

      // Params used for action selection + key lookups. Merge any explicit
      // params with the origin (so a bare `origin` still feeds params.<x> keys
      // when the schema's keyField names that param — the proxy sets origin to
      // the param value).
      const params: Record<string, unknown> = { ...(req.params ?? {}) };

      const branch = selectSchemaBranch(spec, params);
      if (branch === null) {
        // Action-dispatched tool with no matching action and no default.
        return {
          trust: "UNTRUSTED",
          category: null,
          reason: `fail-closed: tool '${req.tool}' action unmatched, no default schema`,
        };
      }

      // No field path → the whole result is classified against the branch.
      if (!req.field) {
        if (isFieldMarker(branch)) {
          return trustFromMarker(branch, req.origin, params, categories);
        }
        // Structured (object/array) schema: the live proxies classify the
        // WHOLE flattened result, which a per-field schema can never match. A
        // spec may declare an explicit whole-result rule for that call shape
        // (schema-types.ts ToolInboundSpec.wholeResult — e.g. WebFetch keys
        // the flattened body off params.url). Resolved like any other leaf;
        // absent ⇒ fail closed below, exactly as before.
        if (!isActionSpec(spec) && spec.wholeResult !== undefined) {
          return trustFromMarker(spec.wholeResult, req.origin, params, categories);
        }
        // Object/array schema, no field given, no whole-result rule — we can't
        // classify a single value against a multi-field schema, so fail closed.
        return {
          trust: "UNTRUSTED",
          category: null,
          reason: `fail-closed: tool '${req.tool}' has a structured schema but no field given`,
        };
      }

      const nav = navigateToMarker(branch, splitFieldPath(req.field));
      if (nav === null) {
        // Field not described by the schema → deny-by-default (matches
        // walkSchema's unknown-key UNTRUSTED semantics for strings).
        return {
          trust: "UNTRUSTED",
          category: null,
          reason: `fail-closed: field '${req.field}' not in tool '${req.tool}' schema → symbolize`,
        };
      }
      if (isFieldMarker(nav.node)) {
        return trustFromMarker(nav.node, req.origin, params, categories);
      }
      // The path resolved to an interior node (object/array), not a leaf — the
      // caller must address a concrete leaf field. Fail closed.
      return {
        trust: "UNTRUSTED",
        category: null,
        reason: `fail-closed: field '${req.field}' resolves to a sub-object, not a leaf`,
      };
  }

  /**
   * The path rules' reading of a request (`classify`'s confidentiality half
   * after its whole-value shortcuts): its origin and input read in both
   * HOMEs, and, for a tool the session's spec does not map, every string of
   * its input. `lookup` is the label lookup to read through: the engine's
   * own for `classify`, a counterfactual one for `pathLevelWith`
   * (clean-tree-release.md R4).
   */
  const pathLabel = (req: ClassifyRequest, lookup: LabelLookup | undefined): {
    label: ReturnType<typeof labelForClassify>;
    namedFiles: string[] | undefined;
    wide: { level: ConfidentialityLevel; bindings: string[]; rule?: string | null } | null;
  } => {
    // Which of the session's AGENT's tools act on a `workdir` (its own gate
    // surface's table, never the request's): a `workdir` on any other call
    // is the model's claim and is not read (callWorkdir; 2026-10-11).
    const workdirTools = sessionWorkdirTools(req, sessionSpecs);
    const labelArgs = req.originHuman || req.paramsHuman
      ? {
          ...req,
          origin: req.originHuman ?? req.origin,
          params: req.paramsHuman ?? req.params,
          pathBase: relativePathBase(req, sessionSpecs),
          workdirTools,
        }
      : { ...req, pathBase: relativePathBase(req, sessionSpecs), workdirTools };
    // Plan 10 §11.13 (2026-10-17): the catalog's `~` places (and `~` in a
    // command) are the session's launch HOME as well as the arbiter's own,
    // the stricter deciding: a launch HOME only adds places. Before, a
    // launch under another HOME had its HOME's files judged by the
    // arbiter's, which named none of them.
    const launchHome = opts.sessionHome?.(req.sessionKey) ?? null;
    const ownLabel = labelForClassify(labelArgs, undefined, lookup);
    const launchLabel = launchHome === null ? null : labelForClassify(labelArgs, launchHome, lookup);
    const label = launchLabel !== null && maxConfidentiality(ownLabel.level, launchLabel.level) !== ownLabel.level ? launchLabel : ownLabel;
    // A tool the session's spec does not map (plan 10 §11.11): its paths
    // may sit under any key, or in a shell command under another name, so
    // every string of its input is read too, in both spellings. Raise-only.
    // Plan 15 §13.12: the files every secret reading was placed on. For a
    // tool the spec does not map, its every string was read too (below),
    // and each of those readings must be placed as well.
    let namedFiles = label.files;
    if (!inboundSpecNamesInput(req.tool, req.sessionKey, sessionSpecs)) {
      // exclusion-flags.md: a shell tool's command field (`command` /
      // Codex's `cmd`) with each `--exclude-dir=NAME` word of one plain
      // grep blanked, as labelForClassify reads it; every other string, and
      // every other tool's, as is.
      const shellTool = ["Bash", "bash", "shell", "exec_command", "local_shell", "exec"].includes(req.tool);
      const blankCommand = (x: Record<string, unknown> | undefined): Record<string, unknown> | undefined => {
        if (x === undefined || !shellTool) return x;
        const out = { ...x };
        for (const k of ["command", "cmd"]) if (typeof out[k] === "string") out[k] = withoutGrepExclusions(out[k] as string);
        return out;
      };
      const inputs = [blankCommand(req.params), blankCommand(req.paramsHuman)].filter((x) => x !== undefined);
      const baseDir = callWorkdir(req.tool, req.paramsHuman ?? req.params, req.workdirDefault, req.callStartDir, workdirTools);
      const ownWide = labelForUnmappedInput(inputs, undefined, lookup, baseDir);
      const launchWide = launchHome === null ? null : labelForUnmappedInput(inputs, launchHome, lookup, baseDir);
      const wide = launchWide !== null && maxConfidentiality(ownWide.level, launchWide.level) !== ownWide.level ? launchWide : ownWide;
      if (isSecret(wide.level)) namedFiles = wide.files !== undefined && (label.files !== undefined || !isSecret(label.level)) ? [...new Set([...(label.files ?? []), ...wide.files])].sort() : undefined;
      return { label, namedFiles, wide };
    }
    return { label, namedFiles, wide: null };
  };

  return {
    classify(req: ClassifyRequest): ClassifyResult {
      // TRUST sees the request EXACTLY as it arrived — `originHuman` is invisible
      // here, by construction. A spelling translation must never be able to move a
      // datum from UNTRUSTED to TRUSTED.
      //
      // Integrity axis OFF (integrity-flag.ts): trust classification is
      // neutralized at this single source — TRUSTED for every field, so no
      // untrusted symbol is ever minted and every downstream integrity gate
      // collapses. The confidentiality derivation below is deliberately
      // untouched: a TRUSTED-but-secret datum must still symbolize.
      let base: ClassifyResult = integrityEnabled
        ? classifyTrust(req)
        : {
            trust: "TRUSTED",
            category: null,
            reason: "integrity axis OFF — trust classification disabled",
          };
      // Exec-output upgrades (exec-routing.md §8.4 — rung 1 exact-match,
      // rung 2 clean-verdict): consulted ONLY on an UNTRUSTED base verdict, so
      // both are upgrade-only by construction — they can never downgrade, and
      // the harness-shape / schema TRUSTED paths above are untouched. The
      // confidentiality derivation below still runs on the upgraded verdict:
      // a secret-labeled datum symbolizes at the proxy even when
      // integrity-TRUSTED.
      if (base.trust === "UNTRUSTED") {
        const upgraded =
          classifyExactContextEcho(req) ??
          classifyExecCleanUpgrade(req, opts.execCleanLookup);
        if (upgraded) base = upgraded;
      }
      // Axis OFF: byte-identical result — no confidentiality field at all
      // (confidentiality.md §11 kill switch, §12 matrix fold 2).
      if (!confidentialityEnabled) return base;
      // The Read dedup notice (confidentiality.md §7.1, "The Read dedup
      // notice", tour item 5): Claude Code answers a re-Read of an unchanged
      // file with its own fixed sentence INSTEAD of the file. Masked at the
      // file's path-derived level, it reached the model as a symbol that
      // stood for the harness's words, the model quoted that symbol as the
      // file, and the reply filter showed the user the notice as the file's
      // content. The notice holds no file byte, so it is PUBLIC — but only
      // when the WHOLE value is exactly a dedup shape (isReadDedupNotice),
      // under the claude-code spec's own `Read` (an explicit override still
      // wins), whole-result only. Anything appended, a near-match, another
      // tool: the path-derived level below stands. The value backstop in the
      // arbiter's classify op still runs on this verdict (raise-only).
      if (
        !req.field &&
        getToolInboundSpec(req.tool, req.sessionKey, sessionSpecs) === CLAUDE_CODE_INBOUND_SPEC.Read &&
        isReadDedupNotice(req.value, req.tool, req.params)
      ) {
        return {
          ...base,
          reason: `${base.reason}; read dedup notice: the value is exactly Claude Code's "file unchanged" answer, no file byte in it → public (confidentiality §7.1)`,
          confidentiality: "public",
        };
      }
      // A write's own notice (plan 15 §13.10, confidentiality.md §7.1 "The
      // write notice"): Claude Code's Write, OpenCode's (1 and 2), Goose's
      // and OpenClaw's `write` answer a whole-content write with a fixed
      // sentence whose only free spans are the call's own path and (Goose,
      // OpenClaw) a count of its content (own-write-notice.ts). Masked at the path's level, a HIGH session's
      // Write to its own derived-labelled file came back to the model as
      // `$MDU:anymodel_Write[…]`. The notice holds no byte the model did not
      // write and no byte of the file, so it is PUBLIC; only when the WHOLE
      // value is exactly a notice for this call, under that agent's own
      // built-in write entry (an explicit tool rule still wins). The value
      // backstop in the arbiter's classify op still runs (raise-only).
      if (!req.field) {
        const agent = ownWriteNoticeAgent(req);
        if (agent !== null && isOwnWriteNotice(agent, req.value, req.params)) {
          return {
            ...base,
            reason: `${base.reason}; write notice: the value is exactly ${req.tool}'s own success notice for this call, no byte the model did not write → public (plan 15 §13.10)`,
            confidentiality: "public",
          };
        }
      }
      // The structured read-twin rule (plan 10 §2.4) is a CONFIDENTIALITY
      // verdict, so it runs here on both axis settings: the rendering is the
      // twin this arbiter minted (keys + field tokens, no secret byte), which
      // is public by construction. The file's label stays on the field rows,
      // where the egress gate reads it.
      if (isStructuredTwinRead(req)) {
        return {
          ...base,
          reason: `${base.reason}; structured read-twin: no secret byte in the rendering (plan 10 §2.4)`,
          confidentiality: "public",
        };
      }
      // "A document's own twin" (plan 10 §11.8), the read leg: the rendering
      // is exactly the document's whole-file twin, its own base token. The
      // document's label stays on that row, where the egress gate reads it.
      if (isWholeFileTwinRead(req)) {
        return {
          ...base,
          reason: `${base.reason}; whole-file read-twin: the rendering is the document's own token, no secret byte (plan 10 §11.8)`,
          confidentiality: "public",
        };
      }
      // "A config with no secret" (plan 10 §11.13, 2026-10-17), the read
      // leg: the rendering is a piece of a registered config's OWN-TEXT twin
      // (an exhaustive shape whose every secret place was read and found
      // public). The value backstop in the arbiter's classify op still runs
      // (raise-only): a registered value, an old field of the file included,
      // masks it.
      if (isOwnTextTwinRead(req)) {
        return {
          ...base,
          reason: `${base.reason}; own-text read-twin: the rendering is a piece of a config Mandu found no secret in (plan 10 §11.13)`,
          confidentiality: "public",
        };
      }
      // CONFIDENTIALITY prefers the HumanView spelling when the caller supplied
      // one (Plan 9): the label stores and the catalog are keyed in HumanView, and
      // under an fs view map the raw `origin` is the AgentView twin — which
      // matches nothing, so a labeled file would classify `public`.
      //
      // BOTH must be translated. `labelForClassify` takes the MAX over the origin
      // and the path-ish params — so an untranslated param keeps hitting the
      // CATALOG (a basename shape like `.env` survives any prefix change), and that
      // hit then OVERRIDES the human's label. It cannot leak (max only raises), but
      // it silently defeats §6's DECLASSIFICATION, which is the utility half of the
      // label store: the fixture `.env` a human marked public stays strict forever.
      const { label, namedFiles, wide } = pathLabel(req, opts.labelLookup);
      if (wide !== null && maxConfidentiality(label.level, wide.level) !== label.level) {
        return {
          ...base,
          reason: `${base.reason}; unmapped tool: its input names ${wide.rule ?? "a labeled path"} (plan 10 §11.11)`,
          confidentiality: wide.level,
          ...(wide.bindings.length > 0 ? { bindings: wide.bindings } : {}),
        };
      }
      return {
        ...base,
        confidentiality: label.level,
        // Omit rather than send [] — an absent field reads as "no standing
        // release", which is what it is, and keeps the wire minimal.
        ...(label.bindings.length > 0 ? { bindings: label.bindings } : {}),
        ...(label.paths.length > 0 ? { namedPaths: label.paths } : {}),
        ...(namedFiles !== undefined && isSecret(label.level) ? {
          namedFiles, placedFiles: label.placed ?? [],
          // only the command's own reading's: a tool the spec does not map
          // adds the files of its every string (above), placed one way only
          ...(label.ifCdFailed !== undefined && namedFiles === label.files ? { ifCdFailed: { dir: label.ifCdFailed.dir, namedFiles: label.ifCdFailed.files, placedFiles: label.ifCdFailed.placed } } : {}),
        } : {}),
      };
    },
    callWorkdirOf(req: ClassifyRequest): string | undefined {
      const p = (req.paramsHuman ?? req.params ?? {}) as Record<string, unknown>;
      return callWorkdir(req.tool, p, req.workdirDefault, req.callStartDir, sessionWorkdirTools(req, sessionSpecs));
    },
    pathLevelWith(req: ClassifyRequest, lookup: LabelLookup): ConfidentialityLevel {
      if (!confidentialityEnabled) return "public";
      const { label, wide } = pathLabel(req, lookup);
      return wide === null ? label.level : maxConfidentiality(label.level, wide.level);
    },
    desymbolizationDecision(req: DesymbolizationRequest): DesymbolizationDecision {
      return decideDesymbolization(req, symbolLookup, (dest) => {
        const url = categories.get("URL");
        // No URL category registered → cannot prove the destination is trusted
        // → fail-closed (untrusted).
        if (!url) return false;
        return url.classify(dest) === "TRUSTED";
      }, { confidentiality: confidentialityEnabled });
    },
    desymbolizationDecisionWith(req: DesymbolizationRequest, lookup: SymbolLookup): DesymbolizationDecision {
      // Byte-for-byte the gate above with the lookup swapped — the tester's
      // probe entry stands in for the symbol table (§5 "Tester ≡ gates").
      return decideDesymbolization(req, lookup, (dest) => {
        const url = categories.get("URL");
        if (!url) return false;
        return url.classify(dest) === "TRUSTED";
      }, { confidentiality: confidentialityEnabled });
    },
    fsPathDecision(req: FsPathDecisionRequest): FsPathDecision {
      return decideFsPath(req, {
        // The DIR trust category doubles as the out-of-workspace allowlist —
        // but ONLY in allowlist mode. The intrinsic default is BLOCKLIST-empty
        // (everything classifies TRUSTED there — an ingress-trust semantic);
        // honoring that here would allowlist the whole filesystem. In blocklist
        // mode the gate ignores DIR and the fail-closed default stands.
        isDirTrusted: (p) => {
          const dir = categories.get("DIR");
          return dir?.mode === "allowlist" && dir.classify(p) === "TRUSTED";
        },
      });
    },
    policySnapshot(): PolicyRuleSnapshot {
      return snapshotActivePolicy(categories);
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Data-usage policy: the egress / desymbolization gate (design §1, §4).
//
// FAIL-CLOSED CONTRACT: deny (requireApproval) unless the resolution is
// PROVABLY safe. The only ALLOW paths are:
//   (a) the symbol is unknown to the table — there is nothing secret to leak, so
//       resolving the literal text is a no-op (and the symbol-table resolve will
//       just leave it as-is). We allow but flag it.
//   (b) a known (untrusted) symbol flowing to a non-command, trusted/local sink:
//       plain user-facing model output, the Agent file system, or a network
//       destination the URL trust category marks TRUSTED.
//
// Every known symbol is, by the Mandu ingress invariant, UNTRUSTED — the proxy
// only ever symbolizes untrusted data. So a known symbol used as a command/code
// (`asCommand`) or sent to an untrusted destination ALWAYS requires approval.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Decide whether a symbol may be desymbolized on egress.
 *
 * @param lookup            resolve a symbol → provenance (undefined = unknown).
 * @param isDestTrusted     is a network destination string TRUSTED?
 */
/**
 * Does an egress destination match one of a datum's bound destinations
 * (confidentiality.md §2.2)? The one binding rule (host-bindings.ts): a bare
 * host admits itself and every host under it ("api.example.com" under
 * "example.com"; "evil-example.com" is not), `*.suffix` every host under
 * the suffix but not the suffix itself, `host:port` only that port.
 * Case-insensitive.
 */
export { destinationMatchesBindings } from "./host-bindings.js";

/**
 * The wire twin's scheme rule (plan 10 §11.13.1, maintainer decision
 * 2026-10-03): a credential whose declared URL or registry is https
 * (`required === "https"`, registry.ts `wireReleaseScheme`) is never put back
 * in a network request that is not stated to be HTTPS: plain HTTP, or a
 * caller that does not say (fail-closed). A HARD refusal (no approval): it
 * runs before any standing human verdict, so an earlier "allow at this host"
 * cannot carry the credential over plain HTTP. Every `network` ask is
 * judged, whatever it says of command use: `asCommand` exempts nothing here
 * (2026-10-10; it did, so such an ask over plain HTTP went on to a standing
 * verdict, as the position rule's own copy of it did).
 * Null = this rule does not apply (not a network release, not a wire
 * credential, an `http://`-declared one, or HTTPS). Pure.
 */
export function wireSchemeRefusal(
  req: Pick<DesymbolizationRequest, "boundary" | "destination" | "scheme">,
  required: "https" | "any" | null,
): DesymbolizationDecision | null {
  if (req.boundary !== "network" || required !== "https" || req.scheme === "https") return null;
  const how = req.scheme === "http" ? "a plain-HTTP request" : "a request whose scheme the caller did not state";
  return {
    allow: false,
    requiresApproval: false,
    reason: `a credential declared for https is never put back in ${how}${req.destination ? ` to '${req.destination}'` : ""}: use https (plan 10 §11.13.1)`,
    ruleRef: ruleRef("egress:secret-https-only"),
  };
}

/** How a refusal names each position. */
const POSITION_WORDS: Readonly<Record<RequestPosition, string>> = {
  authorization: "Authorization header", url: "URL", header: "other headers", body: "body",
};

/**
 * The wire twin's position rule (plan 10 §11.13.1, 2026-10-09): a credential
 * whose release at this destination rests ONLY on an automatic wire binding
 * (`wireOnly`: the launch HOME's `.npmrc` token or pip index password at the
 * host its own file or variable names, an agent key at the provider its auth
 * grant names; current-bindings.ts `releaseRestsOnWireGrant`) is put back
 * only inside the request's own credential header. The same placeholder in
 * the URL, the body or any other header, or a caller that does not say where
 * it sits, is a HARD refusal (no approval): a host such as a registry
 * publishes what a request's body carries (an `npm publish` document's
 * `description`), and the user never chose that binding. It runs before any
 * standing human verdict, so an earlier "allow at this host" cannot carry the
 * credential out of the header. A binding the user declared (a label's
 * `bindings:`, `env.sources`) makes `wireOnly` false and keeps the
 * whole-request release. Every `network` ask is judged, whatever it says of
 * command use: `asCommand` exempts nothing here (2026-10-10; it did, copied
 * from the scheme rule, so such an ask went on to a standing verdict; the
 * scheme rule dropped it too). Null = this rule does not apply. Pure.
 */
export function wirePositionRefusal(
  req: Pick<DesymbolizationRequest, "boundary" | "destination" | "positions">,
  wireOnly: boolean,
): DesymbolizationDecision | null {
  if (req.boundary !== "network" || !wireOnly) return null;
  // Anything not exactly `authorization` (an unknown word, a non-string, a
  // non-array) counts as a place outside the header: fail closed.
  const positions: unknown[] = Array.isArray(req.positions) ? req.positions : [];
  if (positions.length > 0 && positions.every((p) => p === "authorization")) return null;
  const outside = new Set(positions.filter((p) => p !== "authorization"));
  const named = REQUEST_POSITIONS.filter((p) => outside.has(p));
  const where = positions.length === 0
    ? "a request that does not say where in it the placeholder sits"
    : named.length === outside.size
      ? `its ${named.map((p) => POSITION_WORDS[p]).join(" or ")}`
      : "a place in it outside that header";
  return {
    allow: false,
    requiresApproval: false,
    reason: `a credential bound to${req.destination ? ` '${req.destination}'` : " this host"} only by its own config file or sign-in (not by a binding of yours) is put back only in the request's Authorization header, never in ${where} (plan 10 §11.13.1)`,
    ruleRef: ruleRef("egress:secret-wire-position"),
  };
}

/** Options for decideDesymbolization beyond the classic three arguments. */
export interface DesymbolizationOptions {
  /** The confidentiality-axis kill switch (confidentiality.md §11). OFF
   * (default) ⇒ the secret branches never fire — byte-identical decisions
   * to the integrity-only gate. */
  confidentiality?: boolean;
}

export function decideDesymbolization(
  req: DesymbolizationRequest,
  lookup: SymbolLookup | undefined,
  isDestTrusted: (destination: string) => boolean,
  opts?: DesymbolizationOptions,
): DesymbolizationDecision {
  // Empty/garbage symbol → fail-closed.
  if (!req.symbol || typeof req.symbol !== "string") {
    return {
      allow: false,
      requiresApproval: true,
      reason: "fail-closed: empty/invalid symbol → approval required",
      ruleRef: ruleRef("egress:invalid-symbol"),
    };
  }

  const entry = lookup?.(req.symbol);

  // Unknown symbol: nothing in the table to leak. Resolving is a no-op (the
  // symbol-table resolve will leave the literal untouched). Allow, but say so.
  if (!entry) {
    return {
      allow: true,
      reason: lookup
        ? "symbol unknown to table → no secret to leak; resolution is a no-op"
        : "no symbol lookup wired → symbol treated as unknown; no secret to leak",
      ruleRef: ruleRef("egress:unknown-symbol"),
    };
  }

  // Obsolete symbol (e.g. superseded by a human edit) → fail-closed: we cannot
  // be sure the resolved value is still the intended one.
  if (entry.obsoleted_at != null) {
    return {
      allow: false,
      requiresApproval: true,
      reason: "fail-closed: symbol is obsolete (superseded) → approval required",
      ruleRef: ruleRef("egress:obsolete-symbol"),
    };
  }

  // The symbol is known and active. Integrity is STORED per row since Plan 3
  // (trusted×secret ingress mints trusted-integrity rows); it is consulted
  // only in the secret bound-destination branch below — every other branch
  // keeps the historical "known ⇒ UNTRUSTED" posture, which remains true for
  // every row the integrity-only ingress mints (column default 'untrusted').

  // (0) Confidentiality branches (confidentiality.md §3.2/§5/§7, behind the
  // §11 kill switch). Checked BEFORE the integrity branches: a secret symbol
  // must never ride the "trusted destination → allow" integrity path.
  if (opts?.confidentiality) {
    const level = parseConfidentialityLevel(entry.confidentiality);
    if (isSecret(level)) {
      // model context is a HARD deny — the §3.2 residency claim ("never
      // reaches the model vendor") is by-construction; an approval path
      // would make it contractual. No approval override.
      if (req.boundary === "model_context") {
        return {
          allow: false,
          requiresApproval: false,
          reason: `secret symbol (${level}) must never enter model context → deny (confidentiality §3.2)`,
      ruleRef: ruleRef("egress:secret-model-context"),
        };
      }
      // Filesystem (HumanView) stays allow at every level — the human's own
      // disk is the human's domain; high-session on-disk labeling is Phase B/C.
      if (req.boundary === "filesystem") {
        return {
          allow: true,
          reason: "filesystem egress (HumanView): the human owns their secrets → allow",
      ruleRef: ruleRef("egress:secret-filesystem"),
        };
      }
      // Network (and asCommand/shell fall through to the integrity branches
      // below, which already require approval): the ONLY releases a secret
      // gets are its bound destinations — and because every symbol today is
      // untrusted-integrity, §9 rule (b) still takes ONE human approval per
      // {symbol, destination} even at a bound destination (memoized by the
      // egress-approval queue; a human verdict here IS declassification, §8).
      // A TRUSTED URL category never auto-releases a secret.
      if (req.boundary === "network" && !req.asCommand) {
        if (!req.destination) {
          return {
            allow: false,
            requiresApproval: true,
            reason: `secret symbol (${level}) with unknown destination → approval required`,
      ruleRef: ruleRef("egress:secret-unknown-destination"),
          };
        }
        if (destinationMatchesBindings(req.destination, entry.bindings)) {
          // The §3.2 carve-out proper: a TRUSTED-integrity secret (the
          // user's own key, symbolized by provenance not by distrust) may be
          // released at the exact host it is for with no human in the loop.
          // An untrusted-integrity flow keeps the one-time §9(b) approval.
          if (parseIntegrityLabel(entry.integrity) === "trusted") {
            return {
              allow: true,
              reason: `secret symbol (${level}, trusted integrity) at BOUND destination '${req.destination}' → allow (confidentiality §3.2)`,
      ruleRef: ruleRef("egress:secret-bound-trusted"),
            };
          }
          return {
            allow: false,
            requiresApproval: true,
            reason: `secret symbol (${level}) at BOUND destination '${req.destination}' — untrusted-influenced flow → one-time human approval (confidentiality §9b)`,
      ruleRef: ruleRef("egress:secret-bound-approval"),
          };
        }
        return {
          allow: false,
          requiresApproval: true,
          reason: `secret symbol (${level}) at unbound destination '${req.destination}' → human declassification required (confidentiality §3.2)`,
      ruleRef: ruleRef("egress:secret-unbound"),
        };
      }
    }
  }

  // (1) Untrusted symbol used as command/code → always human approval.
  if (req.asCommand) {
    return {
      allow: false,
      requiresApproval: true,
      reason: "untrusted symbol used as command/code → human approval required (data usage policy)",
      ruleRef: ruleRef("egress:symbol-as-command"),
    };
  }

  // (2) Network egress → the destination must be a TRUSTED URL.
  if (req.boundary === "network") {
    if (!req.destination) {
      return {
        allow: false,
        requiresApproval: true,
        reason: "network egress with unknown destination → approval required (possible exfil)",
      ruleRef: ruleRef("egress:unknown-destination"),
      };
    }
    if (isDestTrusted(req.destination)) {
      return {
        allow: true,
        reason: `network egress to TRUSTED destination '${req.destination}' → allow`,
      ruleRef: ruleRef("egress:trusted-destination"),
      };
    }
    return {
      allow: false,
      requiresApproval: true,
      reason: `untrusted symbol → untrusted destination '${req.destination}' → approval required (data usage policy)`,
      ruleRef: ruleRef("egress:untrusted-destination"),
    };
  }

  // (3) Shell egress (argv/code on a HumanShell) is gated per-command by
  // resolveExecArgv (exec-classify). A bare shell-boundary desym request with no
  // asCommand flag is treated conservatively: a value flowing into a live shell
  // is human-facing, but we cannot see its argv position here, so require
  // approval. (The exec path uses resolveExecArgv, not this branch.)
  if (req.boundary === "shell") {
    return {
      allow: false,
      requiresApproval: true,
      reason: "fail-closed: shell-boundary desym must go through resolveExecArgv (per-command argv gate)",
      ruleRef: ruleRef("egress:shell-boundary"),
    };
  }

  // (4) Filesystem egress: writing a resolved untrusted value to the HumanView
  // FS is human-facing and expected (the dual-view sync owns re-symbolization).
  // The destination is local, not a network exfil sink → allow.
  if (req.boundary === "filesystem") {
    return {
      allow: true,
      reason: "filesystem egress (HumanView): local human-facing sink → allow (dual-view sync re-symbolizes)",
      ruleRef: ruleRef("egress:filesystem-humanview"),
    };
  }

  // (5) Plain user-facing model-context output (a reply rendered to the human).
  // The user is allowed to see the original value — that is the whole point of
  // HumanView. Allow.
  if (req.boundary === "model_context") {
    return {
      allow: true,
      reason: "user-facing output (HumanView): the human may see the original value → allow",
      ruleRef: ruleRef("egress:user-facing-output"),
    };
  }

  // Unreachable in practice (Boundary is a closed union), but fail-closed.
  return {
    allow: false,
    requiresApproval: true,
    reason: "fail-closed: unrecognized egress boundary → approval required",
      ruleRef: ruleRef("egress:unknown-boundary"),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Conservative fail-closed default engine (retained from M0).
//
// A maximally-safe standalone default used where the full engine is not wired
// (e.g. minimal tests, a arbiter started without a policy/symbol table).
// classify() is origin-allowlist-only and UNTRUSTED otherwise;
// desymbolizationDecision() DENIES every egress (requiresApproval) because this
// engine has no symbol table to prove a symbol is unknown/local. Deployments
// that want the real egress gate use createEngineBackedPolicy with a
// symbolLookup wired to the live SymbolMap.
// ─────────────────────────────────────────────────────────────────────────────

export interface DefaultPolicyOptions {
  /** Origins to treat as TRUSTED (exact string match). */
  trustedOrigins?: string[];
}

export function createDefaultPolicyEngine(opts: DefaultPolicyOptions = {}): PolicyEngine {
  const trusted = new Set(opts.trustedOrigins ?? []);
  return {
    classify(req: ClassifyRequest): ClassifyResult {
      if (req.origin && trusted.has(req.origin)) {
        return { trust: "TRUSTED", category: null, reason: `origin '${req.origin}' allowlisted` };
      }
      return {
        trust: "UNTRUSTED",
        category: null,
        reason: "default fail-closed: no trusted-origin match → symbolize",
      };
    },
    desymbolizationDecision(req: DesymbolizationRequest): DesymbolizationDecision {
      if (req.asCommand) {
        return {
          allow: false,
          requiresApproval: true,
          reason: "symbol used as command/code → human approval required (data usage policy)",
        };
      }
      // Network egress to an unknown destination is the classic exfil path.
      if (req.boundary === "network" && !req.destination) {
        return {
          allow: false,
          requiresApproval: true,
          reason: "network egress with unknown destination → approval required",
        };
      }
      return {
        allow: false,
        requiresApproval: true,
        reason: "default engine denies egress (no symbol table to prove the value is safe to resolve)",
      };
    },
    fsPathDecision(req: FsPathDecisionRequest): FsPathDecision {
      // No DIR category on the default engine: workspace roots + built-in
      // sensitive list only; everything else fail-closes (the gate's default).
      return decideFsPath(req);
    },
    policySnapshot(): PolicyRuleSnapshot {
      // The default engine has no category registry; surface its trusted-origin
      // set as a URL allowlist so the snapshot still reflects what it enforces.
      return snapshotActivePolicy({
        list: () => [{ id: "URL", mode: "allowlist", listSize: trusted.size }],
      });
    },
  };
}
