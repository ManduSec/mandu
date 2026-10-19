/**
 * protocol — Mandu arbiter IPC wire protocol (Mandu-new, no reference origin).
 *
 * Transport: Unix-domain socket. Framing: newline-delimited JSON ("NDJSON").
 * Each request is one JSON object on a single line terminated by "\n"; the
 * arbiter replies with exactly one JSON object on a single line, in order.
 *
 * Why NDJSON: zero deps, trivially debuggable (`socat`/`nc`), and language-
 * neutral — the Rust interceptors (anthropic-proxy, fs-supervisor) will speak the
 * same framing. Newlines inside string payloads are JSON-escaped by
 * JSON.stringify, so embedded newlines never break framing.
 *
 * Every request carries:
 *   - `id`: client-chosen correlation id, echoed in the response.
 *   - `op`: the operation name.
 * Every response carries:
 *   - `id`: the request id.
 *   - `ok`: boolean success flag. On false, `error` describes the failure.
 *
 * Operations (M0):
 *   - symbolize     : allocate a symbol for an untrusted value (ingress).
 *   - desymbolize   : resolve symbol references in text back to raw values (egress).
 *   - resolve       : resolve a single symbol name to its raw value.
 *   - classify      : data-trust-policy classification (currently the stub engine).
 *   - ping          : liveness check.
 *
 * Operations (Track A — model-API proxy support):
 *   - handlingPrompt : return the T-LLM system prompt describing how to treat
 *                      symbols (built from the active SymbolFormat). The proxy
 *                      injects this so the privileged model knows the symbol
 *                      contract.
 *   - recordToolCall : record a tool_use decision (toolUseId → name/input) so
 *                      later OS interceptors can correlate a syscall to a known
 *                      tool decision. In-memory / non-persistent for now.
 *
 * Operations (data-usage / exec policy — the egress side):
 *   - desymbolizationDecision : the egress gate. Given a symbol + boundary
 *                      (+ optional destination / asCommand) decide whether the
 *                      symbol may be resolved on egress or requires approval.
 *   - classifyExec   : select AgentShell vs HumanShell for a command argv and
 *                      report the command's canonical identity + reason.
 *   - resolveExecArgv: desymbolize an argv for a chosen shell AFTER the
 *                      data-usage check + command rewriting; returns the argv to
 *                      run plus any items that require human approval.
 *   - execGate       : model-context-layer exec gate (exec-routing.md §3). Given
 *                      a raw shell command string, decide allow/block — blocks
 *                      ONLY an untrusted symbol in command/execution position;
 *                      reports classification + non-blocking evasion signals.
 *
 * Operations (egress-approval queue — the interactive human-approval foundation):
 *   - egressApprovals       : list queued egress-approval entries (optionally
 *                      filtered by status). A NETWORK desymbolizationDecision that
 *                      requires approval upserts a PENDING entry; the dashboard
 *                      reads this queue and the human resolves entries via
 *                      resolveEgressApproval. Newest-resolved first (by lastSeen).
 *   - resolveEgressApproval : set a human verdict (approve/deny, or deny with
 *                      `strip`: "Send without it") on a queued
 *                      entry by id. A SUBSEQUENT desymbolizationDecision for the
 *                      same {symbol, destination} then short-circuits to allow
 *                      (approved) / deny-without-approval (denied).
 *
 * Operations (reply row reservation — docs/design/ui/reply-row-reservation.md):
 *   - symbolShape     : the line count of ONE symbol token's deep-resolved value
 *                      (never the value), and with a `width` the number of
 *                      screen rows it wraps to. The proxy sizes a reserve
 *                      block with it. Human plane only.
 *   - setSessionRelay : the reply filter reports its relay mode (pty / pipe /
 *                      passthrough), whether it can paint reserve blocks (and
 *                      v2 wrapped heads), and the terminal size. In memory,
 *                      per session. Human plane only (§11.5).
 *   - sessionRelay    : read that state back (null when never reported).
 *                      Human plane only.
 *   - noteReserveBlock: the proxy records a block it expanded (the head's
 *                      token, N, and W/F for a v2 head), keyed by session
 *                      and the token's hash. Human plane only (§3.8).
 *   - reserveBlock    : the reply filter reads a block back by hash, for a
 *                      continuation row whose head never reached the
 *                      screen. Human plane only.
 *
 * Operations (the after-the-fact note across a resume — confidentiality.md
 * §7.1, "Masked after the fact"):
 *   - recordForwardedClear: a model proxy records the tool-call ids whose
 *                      result body it forwarded to the model in clear. Ids
 *                      only, durable (mandu.db `forwarded_clear`). Human
 *                      plane only.
 *   - forwardedClear : which of the given ids were recorded (a proxy of a
 *                      later launch, on a resumed history), the store's
 *                      generation, and with `since` the ids recorded after
 *                      it (two launches at once). Human plane only.
 *   - recordForwardedPlaceholders: a model proxy records, for a result it
 *                      forwarded in clear in an OpenClaw session, where
 *                      Mandu's placeholders sat in it and a digest of it
 *                      (confidentiality.md §6, *Across a relaunch*). Tokens,
 *                      offsets and a digest only, durable (mandu.db
 *                      `forwarded_placeholders`). Human plane only.
 *   - forwardedPlaceholders: the records of the given ids (a proxy of a
 *                      later launch rebuilds the text OpenClaw's history
 *                      redaction cut, and checks the digest). Human plane
 *                      only.
 *
 * Operations (observability event stream — the dashboard live feed):
 *   - emit          : append one opaque observability `event` to the per-session
 *                      append-only NDJSON log, assign a monotonic per-session
 *                      `seq`, and fan it out to live subscribers. FIRE-AND-FORGET
 *                      observability ONLY: a failed emit returns an error
 *                      response, but callers MUST NOT gate any security decision
 *                      on emit success — emission is never on the security path.
 *   - events        : read persisted events for a session with seq > sinceSeq.
 *   - sessions      : list known sessions with counts + ts bounds.
 *   - deleteSession : delete ONE session's event log (+ its in-memory seq state
 *                      and live subscriptions) — ANY session, live or test
 *                      (2026-07-11: the original test-only rule was dropped at
 *                      the user's request; protection is the dashboard's
 *                      mutating-route gating + confirm, not an id-class rule).
 *                      Unknown session → error; a traversal-shaped id is still
 *                      rejected by the store's safe-id guard. OBSERVABILITY
 *                      ONLY: the symbol table, policy state and approval queue
 *                      are untouched.
 *   - subscribe     : STREAMING op on a DEDICATED connection — first replays the
 *                      backlog (events since sinceSeq) as frames, then pushes each
 *                      newly-emitted event as it arrives, until the client closes
 *                      the socket. `subscribe` MONOPOLIZES its connection; the
 *                      one-request-one-response ops above are unaffected on other
 *                      connections.
 */

export const PROTOCOL_VERSION = 1;

import type {
  ClassifyRequest,
  ClassifyResult,
  DesymbolizationRequest,
  DesymbolizationDecision,
} from "../policy/policy-interface.js";
import type {
  ExecClassifyDecision,
  ExecShell,
  ResolveExecArgvResult,
} from "../policy/exec-classify.js";
import type { RelayNoticeWire } from "./relay-notices.js";
import type { ExecGateResult } from "../policy/exec-gate.js";
import type { RecordedExecDecision } from "../policy/exec-decision-store.js";
import type {
  ExecCleanVerdict,
  ExecCleanVerdictReport,
} from "../policy/exec-clean-verdicts.js";
import type { ExecTwinCandidate, ExecTwinReport } from "../policy/exec-twin-store.js";
import type {
  FsPathDecisionRequest,
  FsPathDecision,
} from "../policy/fs-outbound.js";
import type { FileUploadDecisionRequest, FileUploadDecision } from "../policy/file-upload.js";
import type { PolicyRuleSnapshot } from "../policy/policy-snapshot.js";
import type { BlockedExecKind } from "../policy/blocked-exec.js";
import type { RuleRef, UsageRule, UsageGate } from "../policy/rule-ref.js";
import type { PolicyLawSource } from "../policy/load-policy.js";
import type { SecretHistoryScan } from "../policy/secret-history-scan.js";
export type { WhySymbolOpResult, WhySymbolFindingWire, WhySymbolVerdictWire, WhySymbolPolicyWire } from "../prompt-filter/why-symbol.js";
import type { CoveredSecret, Suggestion, SuggestionEdit } from "../policy/policy-suggestions.js";
import type { SecretWorkspaceScanSummary } from "../policy/secret-workspace-scan.js";
import type { ModelDestination } from "../policy/policy-model.js";
import type {
  EgressApproval,
  ApprovalStatus,
  ApprovalScope,
} from "../policy/egress-approvals.js";
import type {
  ArbiterEvent,
  StoredEvent,
  SessionSummary,
} from "../events/event-store.js";

// ── Requests ────────────────────────────────────────────────────────────────

export interface BaseRequest {
  /** Client-chosen correlation id, echoed back in the response. */
  id: string | number;
  op: string;
}

/** Allocate a symbol for an untrusted value. Mirrors AllocateSymbolOpts. */
export interface SymbolizeRequest extends BaseRequest {
  op: "symbolize";
  tool: string;
  value: string;
  field?: string;
  origin?: string;
  /** The same origin in the arbiter's own world — HumanView (Plan 9). A caller
   * running an fs view map (the anthropic-proxy under fs-sync, DEFAULT-ON for a
   * git workspace) sees the AgentView twin on the wire, while every path policy
   * here — the catalog, the user labels, the derived labels — is keyed in
   * HumanView. Used ONLY to derive the LEVEL; the stored provenance origin stays
   * `origin` (what the agent actually touched), and TRUST never sees this field. */
  originHuman?: string;
  /**
   * The directory the session's agent resolves a RELATIVE typed path against
   * (ClassifyRequest.relativeBase: the launch directory, HumanView), sent by
   * the anthropic-proxy on the symbolize of a result whose classify carried
   * it. Applied exactly where the classify applies it (`relativePathBase`:
   * the session's own gate surface says `launch` and lists the tool) and only
   * to an `origin` the agent's tool reads as `<base>/<origin>`
   * (`resolveTypedPathOrigin`), with no `originHuman`: the row is then STORED
   * at that absolute path, so its level and BINDINGS are that file's label,
   * at mint and at every later bindings sync (current-bindings.ts rule 2,
   * which reads the stored origin). Without it a relative origin matched no
   * label: the row was secret by the classify's level but bound nowhere, and
   * a declassify of it left the session's bound set empty (2026-10-10,
   * confidentiality.md §6). Ignored while the confidentiality axis is OFF.
   */
  relativeBase?: string;
  sessionKey?: string;
  callId?: string;
  /** Requested confidentiality level (confidentiality.md §2). The server
   * derives the effective level as max(requested, catalog(origin)) — a
   * request can only RAISE. Unknown strings parse fail-closed to
   * "no-model". IGNORED while the confidentiality axis is OFF. */
  confidentiality?: string;
  /** Per-datum bound destinations to store with the symbol (§2). */
  bindings?: string[];
  /** Integrity half of the label (§2): "trusted" only when the ingress
   * classification vouched for the bytes (a TRUSTED×secret result the proxy
   * symbolized). Anything else — absent, junk — stores "untrusted"
   * (fail-closed). IGNORED while the confidentiality axis is OFF. */
  integrity?: string;
  /** Parent symbol name when this value was DERIVED from another symbol
   * (symbol-lineage.md G2): the quarantined U-LLM's re-symbolized result names
   * the inspected input symbol here. Stored in symbols.derived_from —
   * provenance only, never part of the reuse key. */
  derivedFrom?: string;
  /** Line span within the parent value for a derived symbol, end-exclusive
   * `start:end` (the allocateDerivedSymbol format). Stored in
   * symbols.line_range; meaningful only alongside derivedFrom. */
  lineRange?: string;
  /** The value is an agent's WHOLE tool result and starts with the head that
   * agent's runtime writes (plan 10 §11.14). Known kinds: `"codex"` (Codex's
   * exec / script-cell head), `"codex-mcp"` (Codex's MCP call head),
   * `"claude-task"` (Claude Code's BashOutput / TaskOutput status tags) and
   * `"write-notice"` (a write tool's fixed success sentence for the row's own
   * origin, plan 15 §13.10; a write tool's row only), each matched by the
   * arbiter's own exact grammar at offset 0 (policy/agent-result-head.ts). Its lines are then not fingerprinted as
   * lines of the registered value (the whole value still is, and every line
   * after the head). Absent, unknown, or a value that does not start with
   * exactly that kind's grammar: every line is fingerprinted. Not part of the
   * reuse key; stored with the row, bound to its value (result_heads), so a
   * restart keeps it. */
  resultHead?: string;
  /** `"value-backstop"`: the requested level is exactly the classify verdict
   * the arbiter's value backstop raised for this call (`raisedBy` on the
   * classify result), and the caller raised it no further (no taint, no
   * agent-receipt raise). The arbiter then registers, of the row's long
   * lines, only those a registered secret was found in, after checking its
   * own record of the call's classify, the row's origin label and the call's
   * taint (plan 15 §13.11, "What a raised row registers"). It never lowers
   * the level. `path-rule`: the level is the classify's own path-derived
   * level (the command names a secret path) and the caller raised it no
   * further; the arbiter then registers the same lines after checking its
   * record (the path rule alone, each reading placed on a file), the call's
   * tree (bound, no raw read) and that each file is registered as it is on
   * disk (plan 15 §13.12, "What a path row registers"). Absent or anything
   * else: every line is registered. Not part of the reuse key. */
  secretBy?: string;
}

/** Replace every symbol reference in `text` with its raw value — RECURSIVELY
 * (fixpoint): a resolved value that itself contains symbols (the fs-sync twin
 * double-symbolization) is expanded too, so the HumanView surface this op
 * serves (fs-sync syncToHuman) always receives original data. Per-symbol
 * GATED egress paths must NOT use this op — they resolve one approved symbol
 * at a time via `resolve` (shallow). */
/** Multi-source derivation requires a new op: old arbiters must refuse, never
 * silently ignore parent-label inheritance. */
export interface SymbolizeDerivedRequest extends Omit<SymbolizeRequest, "op"> {
  op: "symbolizeDerived";
  sourceSymbols: string[];
}

export interface DesymbolizeRequest extends BaseRequest {
  op: "desymbolize";
  text: string;
}

/** Resolve one symbol name to its raw value (null if unknown).
 * `deep` additionally expands symbols nested INSIDE that value to fixpoint —
 * for ungated full-fidelity consumers only (the quarantined U-LLM's
 * inspect_symbol). Gated egress callers (net-proxy, net-supervisor), which
 * approve each symbol individually before resolving, must stay shallow so a
 * nested symbol cannot ride out under the outer symbol's approval. */
export interface ResolveRequest extends BaseRequest {
  op: "resolve";
  symbol: string;
  deep?: boolean;
  /** Plan 11 D4, `deep` only: the name of the declared model endpoint the
   *  resolved value is for. The arbiter looks it up in its own registry
   *  (policy.yaml `models:`); absent or undeclared means external. Admission
   *  is `admits(location, level)` for the top value AND every nested one. */
  endpoint?: string;
}

/** The tool call that produced a symbol's value (symbol-quality.md §4.1 v2):
 * TCB-recorded linkage symbol.call_id → recordToolCall. Read-only and
 * BEST-EFFORT — any missing link (no call_id on the entry, no recorded tool
 * call, an arbiter restart losing the in-memory records) yields nulls, and
 * consumers degrade to provenance-free behavior. The returned toolName/
 * toolInput are T-LLM-AUTHORED (the privileged principal's own tool call),
 * not untrusted data. */
export interface SymbolProvenanceRequest extends BaseRequest {
  op: "symbolProvenance";
  symbol: string;
}

export interface SymbolProvenanceResult {
  /** Original mint-time field, never decoded from the wire name. Present for
   * known rows (null means no field); absent for unknown/older servers. */
  field?: string | null;
  /** The mint-time tool tag on the symbol entry (e.g. "Bash"), or null when
   * the symbol is unknown. */
  tool: string | null;
  /** The originating tool_use id recorded at symbolize time, or null. */
  callId: string | null;
  /** The recorded tool call's name/input (recordToolCall), or null/undefined
   * when no record exists (not recorded, or lost to an arbiter restart). */
  toolName: string | null;
  toolInput?: unknown;
}

/** Data-trust-policy classification for an inbound value. */
export interface ClassifyOpRequest extends BaseRequest {
  op: "classify";
  request: ClassifyRequest;
}

export interface PingRequest extends BaseRequest {
  op: "ping";
}

/** Identity handshake (runtime-instances.md): WHO is listening — pid, git rev,
 * start time, instance id, and the durable-state paths. Lets the dashboard
 * supervisor / clients detect a STALE or foreign daemon instead of silently
 * adopting whatever answers the socket. */
export interface HelloRequest extends BaseRequest {
  op: "hello";
}

/** Session-health (dashboard.md §4.21): the tool battery an agent advertised.
 * The arbiter answers which names the session's ACTIVE inbound spec does not
 * know — their outputs fail closed (symbolized whole), a utility loss the
 * proxy records as a `tool_surface` event and the dashboard flags per session.
 * A new Claude Code release adding a tool is exactly the drift this catches. */
export interface ToolSurfaceRequest extends BaseRequest {
  op: "toolSurface";
  names: string[];
  sessionKey?: string;
}
export interface ToolSurfaceResult {
  /** Advertised names with no inbound spec (fail-closed on ingress). */
  unknown: string[];
}

/** Which of the session's agent tools each model-context gate reads, and from
 * which input field (policy/tool-gate-surface.ts; agent-e2e-harness.md §7.7).
 * Resolved from the session's bound inbound spec, else the process-global one;
 * a spec with no gate table answers the UNION of every agent's table
 * (fail-closed: never less gating than the Claude Code table). Read-only. */
export interface GateSurfaceRequest extends BaseRequest {
  op: "gateSurface";
  sessionKey?: string;
}
export interface GateSurfaceResult {
  spec: string;
  exec: Record<string, string>;
  execOutput: Record<string, string>;
  net: Record<string, { destination: string | null; symbols: string; alsoDestinations?: string[]; block?: "refuse" }>;
  paths: Record<string, { fields: string[]; mode: "read" | "write"; refs?: "media" }>;
  /** Dispatcher tools (tool-gate-surface.ts DispatchKind). */
  dispatch: Record<string, "openclaw-tool-call" | "refuse">;
  /** Tools refused on every call: tool → why (tool-gate-surface.ts RefuseTable). */
  refuse: Record<string, string>;
  /** Tools refused in some forms (tool-gate-surface.ts RefuseArgRule). */
  refuseArgs: Record<string, Array<{ field: string; allow: string[]; reason: string }>>;
  /** Tools that type into a running process (tool-gate-surface.ts StdinKind). */
  stdin: Record<string, "openclaw-process">;
  /** Tools whose target paths live inside a patch text (tool-gate-surface.ts
   *  PatchToolFields). */
  patch: Record<string, { field: string; format: "apply-patch" }>;
  /** Where the agent resolves a relative path (tool-gate-surface.ts
   *  relativeBase); absent = not known to the proxy. */
  relativeBase?: "launch";
  /** The agent attaches files its model names in the reply text
   *  (tool-gate-surface.ts ReplyMediaKind); null = it does not. */
  replyMedia?: "openclaw-media-lines" | null;
}

/** Fetch the T-LLM system prompt that teaches the model how to treat symbols.
 * Built via buildSymbolSystemPrompt(activeFormat, { mode, capabilities }). The
 * model-API proxy injects the returned string into the system context. */
export interface HandlingPromptRequest extends BaseRequest {
  op: "handlingPrompt";
  /** Mandu operation mode passed through to buildSymbolSystemPrompt. Defaults
   * to "full". "dual-only" selects the stricter command-agnostic exec contract. */
  mode?: "full" | "dual-only";
  /** Tool-battery capability FACTS reported by the proxy (from the request's
   * `tools` array); the arbiter maps them to prompt sections. Every ABSENT
   * field defaults to present, so an absent object — e.g. an older proxy —
   * yields the full prompt. Utility surface only: over-reporting costs tokens,
   * never security (symbolization/egress gates enforce the invariant). Wire
   * mirror of symbol-table/handling-prompt.ts HandlingPromptCapabilities. */
  capabilities?: {
    /** An inspect_symbol tool is available (gates inspect/content_kind guidance). */
    inspect?: boolean;
    /** policy_list/policy_add/policy_del are available (gates Data Trust Policy). */
    policyTools?: boolean;
    /** The Mandu policy tools (mandu_policy_read/_test/_propose) are
     *  available; gates "Setting up protection". Absent = FALSE. */
    manduPolicy?: boolean;
    /** A shell/exec tool is available (gates the exec-modes section). */
    exec?: boolean;
    /** The exec tool's declared input schema has an `env` parameter, so the
     * RESTRICTED=1 opt-in is expressible. FALSE ⇒ the exec section drops the
     * env mechanism (a schema-validating harness rejects the whole call).
     * Absent = true (older proxy → today's full guidance). */
    execEnv?: boolean;
    /** The session runs with a HumanView↔AgentView view map (fs rung), so
     * untrusted workspace files are whole-file symbol twins; gates rule R9
     * "the file view". Absent = FALSE (symbol-twin-shell-blindness.md §4.5). */
    fsView?: boolean;
    /** The launch's secret posture (the proxy's MANDU_SECRET_POSTURE, set by
     *  the launcher): `read-blocked` (macOS) adds the section saying that
     *  credential-file reads fail by design (handling-prompt.md §2). Absent =
     *  no section. */
    secretPosture?: string;
    /** A browser agent's model (the egress proxy's report for a program's
     *  own call to a model service): adds the *Web pages* section with the
     *  confidentiality axis ON. Absent = FALSE (handling-prompt.md §11). */
    browser?: boolean;
  };
  /** The session the prompt is for (the proxy's MANDU_SESSION_KEY). With it
   *  the arbiter reads the session's main-model binding
   *  ({@link SetSessionUpstreamRequest}) and tells the model whether
   *  `declassify_symbol` can open a `local-model` symbol (plan 11 phase 3).
   *  Absent = the main model is treated as an outside one (the strict text). */
  sessionKey?: string;
}

/** Record a tool_use decision so later OS interceptors can correlate a syscall
 * to a known tool decision. Stored in an in-memory map keyed by toolUseId
 * (non-persistent for now). */
export interface RecordToolCallRequest extends BaseRequest {
  op: "recordToolCall";
  /** The Anthropic `tool_use.id` for this call. */
  toolUseId: string;
  /** The `tool_use.name` (e.g. "Bash", "Read", "mcp__server__tool"). */
  name: string;
  /** The tool input object as sent by the model. */
  input: unknown;
  /** Optional session/agent scope key for multi-agent correlation. */
  sessionKey?: string;
}

/** Data-usage / egress gate: may this symbol be resolved at this boundary?
 *  A `network` ask states the request's `scheme` and the symbol's
 *  `positions` in it when the caller knows them: a wire-twin credential is
 *  refused without `https` (`egress:secret-https-only`), and one bound only
 *  automatically is refused outside the Authorization header
 *  (`egress:secret-wire-position`), both before any standing verdict. */
export interface DesymbolizationDecisionOpRequest extends BaseRequest {
  op: "desymbolizationDecision";
  request: DesymbolizationRequest;
}

/** Sensitive-path gate (fs data-usage policy, fs-sync.md §1.4.1): may
 * tool T touch absolute path P? Asked by the context proxy at the response-side
 * tool_use hook; wrapped by the egress-approvals queue (key `fs:<tool>` × path). */
export interface FsPathDecisionOpRequest extends BaseRequest {
  op: "fsPathDecision";
  request: FsPathDecisionRequest;
}

/** The local-file upload gate (file-upload.ts; supported-agents.md §2): may
 * tool T send the bytes of the absolute path P to host D? Asked by the
 * context proxy for Claude Code's DesignSync `write_files{localPath}`, on
 * the human plane; wrapped by the egress-approvals queue (key
 * `fs:<tool>:upload` × path). From the data socket it never reads a file.
 * Asynchronous: the file is scanned in chunks (upload-scan.ts). */
export interface FileUploadDecisionOpRequest extends BaseRequest {
  op: "fileUploadDecision";
  request: FileUploadDecisionRequest;
  /** The client understands progress frames (`{id, progress: true}`, every
   *  `FILE_UPLOAD_PROGRESS_MS` while the scan of a large file runs), so it
   *  can wait for the scan without waiting as long on an arbiter that never
   *  answers. Absent: no frame is sent. */
  progress?: boolean;
}

/** Select AgentShell vs HumanShell for a command argv. */
export interface ClassifyExecOpRequest extends BaseRequest {
  op: "classifyExec";
  /** The command argv (argv[0] is the program). */
  argv: string[];
  /** Working directory the command runs in. */
  cwd?: string;
  /** Caller resource hints — when either is true, route to HumanShell. */
  needsNetwork?: boolean;
  needsOriginalFs?: boolean;
  /** Exec params (e.g. { env: { RESTRICTED: "1" } } pins AgentShell). */
  params?: Record<string, unknown>;
}

/** Desymbolize an argv for a chosen shell after the data-usage check. */
export interface ResolveExecArgvOpRequest extends BaseRequest {
  op: "resolveExecArgv";
  argv: string[];
  shell: ExecShell;
  params?: Record<string, unknown>;
}

/** Model-context-layer exec gate (exec-routing.md §3): classify a raw shell
 * command string and decide allow/block. Blocks ONLY an untrusted symbol in
 * command/execution position; data-position symbols stay opaque (not
 * over-blocked). Asked by the model proxies at the response-side tool_use hook.
 * The arbiter also RECORDS the verdict by command signature so the exec
 * supervisor can correlate it later (exec-routing.md §4 step 1). */
export interface ExecGateOpRequest extends BaseRequest {
  op: "execGate";
  /** The raw shell command as the model wrote it (symbols still opaque). */
  command: string;
  /** Working directory the command would run in. */
  cwd?: string;
  /** Optional session tag stored with the recorded decision (observability). */
  sessionKey?: string;
  /** The tool_use id this command belongs to (the proxy knows it; the OS side
   * does not). Recorded with the decision so the exec supervisor — which can
   * only look the decision up by command SIGNATURE — learns the callId it must
   * key a clean-verdict report on (exec-routing.md §8.5). Correlation is
   * utility-only: a wrong/missing callId costs an upgrade, never safety (the
   * verdict store's hash binding carries the security). */
  callId?: string;
}

/** Why the egress proxy refused a program's connection, as a fixed kind (the
 * note the model reads is worded by the model proxies from the kind alone:
 * no host, no URL, no request byte). Confidentiality plan 10 §11.8, "Refused
 * connections". */
/** `session-asked` / `session-blocked` (2026-10-12, confidentiality.md §4,
 * "A held command's refused connection"): a HIGH session's held command was
 * refused at a host and the user was asked on the Approvals page (retry
 * after the answer), or the user had blocked that host for the session
 * (final). Recorded by the arbiter itself when it files or reads that
 * answer, and by the net-proxy. */
/** `symbol-destination` (2026-10-17, "A placeholder as the destination"):
 * the host of the request (a CONNECT target, a plain request's host or
 * Host header) carried a $MDU placeholder, which Mandu never resolves into
 * a destination. */
export const EGRESS_REFUSAL_KINDS = ["tainted", "unattributed", "symbol", "fingerprint", "blocked-destination", "this-machine", "shell-expanded", "fail-closed", "session-asked", "session-blocked", "symbol-destination"] as const;
export type EgressRefusalKind = (typeof EGRESS_REFUSAL_KINDS)[number];

/** Plan 10 §11.8 (2026-10-04): the egress proxy refused a connection from
 * these processes. Folded into `callTaint` (`refusedEgress`) for the tool
 * call whose tree holds one of them, so its result says the connection was
 * refused. An attested report (the net-proxy's human client): from the data
 * socket nothing is recorded.
 *
 * "A refusal no process is tied to" (2026-10-17): `procKeys: []` with
 * `unattributed: true` reports a refusal the proxy could not attribute to
 * any process. It is recorded for the session (the kind and a time, never a
 * host, never a guessed process) and folded into every call of the session
 * whose window held it (`refusedEgress` with `unattributed: true`). */
export interface RecordEgressRefusalOpRequest extends BaseRequest {
  op: "recordEgressRefusal";
  /** The sending process and its holders, as the proxy attributed them;
   *  empty only with `unattributed`. */
  procKeys: string[];
  kind: EgressRefusalKind;
  sessionKey?: string;
  /** The proxy found no process holding the connection. */
  unattributed?: boolean;
}

/** Plan 13 D9 follow-up: the command the model proxy DELIVERED to the agent
 * for a tool call, after its own rewrites (the view map's AgentView spelling,
 * a block sentinel), sent before it relays the call. `callTaint` binds the
 * call to the agent's shell by this command (else by `execGate`'s), never by
 * the text the agent echoes back. Believed only on the human socket (an
 * attested report); from the data socket nothing is recorded. */
export interface RecordCallCommandOpRequest extends BaseRequest {
  op: "recordCallCommand";
  callId: string;
  /** Absent (plan 13 §4.5.1, 2026-10-02): a call with no command (WebFetch,
   *  an MCP tool): only its relay time is recorded (`call_pending`), the
   *  start of the window in which the agent's own connections to a holder
   *  mask its result (`agentReceiptTaint`). */
  command?: string;
  sessionKey?: string;
}

/** Correlation lookup (exec-routing.md §4 step 1): fetch the proxy's recorded
 * `execGate` decision for a command, so the exec supervisor can take the MORE
 * RESTRICTIVE of it and its own ground-truth classifyExec. Pass EITHER the raw
 * command string (proxy form) or the observed argv (supervisor form) — both are
 * reduced to the same signature. A miss returns `{ decision: null }`. */
export interface ExecDecisionForOpRequest extends BaseRequest {
  op: "execDecisionFor";
  /** The raw command string, or… */
  command?: string;
  /** …the observed argv (joined + signature-normalized). One of the two. */
  argv?: string[];
}

/** Exec escalation gate (exec-routing.md §5): an AgentShell command that needs a
 * restricted resource (real network / the HumanView filesystem) may only escalate
 * to HumanShell behind a HUMAN approval. Reuses the interactive egress-approval
 * queue (key `exec-escalate:<resource>` × signature): approved → HumanShell;
 * denied/pending/absent → stay AgentShell (fail-safe, pending queued). */
export interface EscalateExecOpRequest extends BaseRequest {
  op: "escalateExec";
  /** The command's observed argv (for the signature + audit). */
  argv: string[];
  /** Working directory (audit). */
  cwd?: string;
  /** Which restricted resource the command needs. */
  resource: "network" | "original-fs";
  /** Optional session tag (audit). */
  sessionKey?: string;
}

/** Report one finished boxed invocation's CLEAN verdict (exec-routing.md §8
 * §4 rung 2 / §5): the exec supervisor's claim, resolved server-side through
 * the fail-closed gate chain (boxed, AgentShell, the arbiter's OWN lineage-
 * taint re-check on procKey, 64-hex outputSha256) and recorded keyed by the
 * tool_use callId. The classify op then consumes it (hash-bound) to upgrade
 * that invocation's tool_result. A report that fails any gate records
 * UNCLEAN with the failing gate named; unclean is monotonic (a later clean
 * report never flips it). */
export interface ReportExecCleanVerdictOpRequest extends BaseRequest {
  op: "reportExecCleanVerdict";
  report: ExecCleanVerdictReport;
  /** The token the session's guard claimed (`claimCleanReporter`). Without a
   *  valid one the report is not honored (exec-routing.md §8.5.3). */
  reporterToken?: string;
}

/** The session's guard claims its clean-verdict reporter token, once, before
 * its agent starts (exec-routing.md §8.5.3, policy/clean-reporters.ts).
 * Refused unless the launcher's first `setSessionUpstream` asked for a
 * reporter; a second claim revokes the reporter for good. */
export interface ClaimCleanReporterRequest extends BaseRequest {
  op: "claimCleanReporter";
  sessionKey: string;
}

export interface ClaimCleanReporterResult {
  token: string;
}

/** Fetch the RESOLVED clean verdict for a callId (observability / tests / the
 * supervisor double-checking what its report resolved to). Null on a miss. */
export interface ExecCleanVerdictForOpRequest extends BaseRequest {
  op: "execCleanVerdictFor";
  callId: string;
}

/** The exec box reports, BEFORE it runs one AgentShell leaf, the paths that
 * leaf named whose AgentView twin is solely symbol tokens
 * (symbol-twin-shell-blindness.md §4.1 v2). Signature-keyed (a pipeline /
 * post-`cd` leaf has no callId), recency-bounded, and a HINT only: the proxy
 * re-applies the twin predicate under its own roots before any note. */
export interface ReportExecTwinsOpRequest extends BaseRequest {
  op: "reportExecTwins";
  report: ExecTwinReport;
}

/** The proxy asks, when it forwards a Bash tool_result, which recent boxed
 * leaves plausibly belong to this model-authored command and what symbolic
 * twins they named. Pure read (nothing consumed). */
export interface ExecTwinsForOpRequest extends BaseRequest {
  op: "execTwinsFor";
  command: string;
}

/** The confidentiality level the arbiter WOULD assign to a value read from
 * `path` right now — the same derivation `symbolize` applies at mint (user
 * labels first, then the default-secret catalog), keyed on the HumanView
 * spelling. fs-sync's re-launch fast path compares it with the level a seeded
 * twin's token carries and re-seeds on a mismatch, so a label added, changed
 * or removed after the seed reaches the AgentView on the next launch
 * (fs-sync.md §3.2). `axis: false` when the confidentiality axis is
 * OFF (every level is then `public` and no twin carries a marker). */
export interface PathLevelOpRequest extends BaseRequest {
  op: "pathLevel";
  path: string;
}

/** The Rules page's file browser (dashboard.md §4.25m): `pathLevel`'s
 * derivation for every entry of one listed folder, in one round trip, plus
 * WHERE the deciding human label is kept so the page can change it in place.
 * Read-only and observability only: nothing is pinned, queued or counted.
 * Unlike `pathLevel` it answers with the axis OFF too (`axis: false`), so the
 * page can show what the labels WILL do once protection is on. */
export interface PathLevelsOpRequest extends BaseRequest {
  op: "pathLevels";
  /** At most {@link PATH_LEVELS_MAX} paths, each absolute or `~/…`. */
  paths: string[];
  /** The launching user's HOME, for `~/` labels and catalog rules. */
  home?: string;
  /** Answer under the law WITH these policy edits (the policy-edit grammar),
   *  nothing written: the browser's "what this change does" (dashboard.md
   *  §4.25m). Same mechanism as `testFlow.withEdits`. */
  withEdits?: unknown;
}

/** Move the rules made on the dashboard before they lived in policy.yaml
 *  (the mandu.db label store) into `paths:`, unchanged, and delete the rows:
 *  one place for every rule, with History and Undo from then on (dashboard.md
 *  §4.25m). ADMIN-ONLY. What is enforced does not change. Recorded as a
 *  `move-labels` change, which Undo refuses (the rows are gone). */
export interface MovePageLabelsOpRequest extends BaseRequest {
  op: "movePageLabels";
  requestedBy?: string;
}

export interface MovePageLabelsResult {
  moved: number;
  /** The recorded change, or null when there was nothing to move. */
  changeId: string | null;
}

/** Cap on one `pathLevels` request (the browser pages a folder at 500). */
export const PATH_LEVELS_MAX = 1000;

/** `mandu why <path>` (comparisons.md §3.2): everything the law says
 * about one file, read-only. Same derivation as the gates (pathLevel,
 * decideSecretOpen's reader list, the consumer table), nothing recorded. */
export interface WhyPathOpRequest extends BaseRequest {
  op: "whyPath";
  path: string;
  /** The launching user's HOME, for catalog `~/` rules (the arbiter's own
   *  HOME may differ, secret-discovery.md §1). */
  home?: string;
  /** The user's values of the variables that move an agent's login file
   *  (discoverSecrets' `loginEnv`), so a moved one is named as a login. */
  loginEnv?: Record<string, string>;
  /** Plan 10 §11.13 (2026-10-17, `mandu why <path> --session <id>`): the
   *  session whose launch HOME the path is judged under as well (human
   *  plane only); absent, the newest live launch's. See
   *  {@link WhyPathOpResult.launch}. */
  session?: string;
}

/** `mandu why <host>`: which secrets are bound to a destination, what the
 * egress gate would do with a bound and an unbound secret sent there, the
 * law's connect allowances for it, and the prior human verdicts. Read-only. */
/** policy.yaml `env.sources` for the launcher to resolve (names, sources and
 * bindings; never a value). Result: `{ sources: EnvSourceWire[] }`. */
export interface EnvSourcesOpRequest extends BaseRequest {
  op: "envSources";
}
/** The signed consumer packs in force. Result: `{ packs: [{name, version, keyId, consumers}], refused: string[] }`. */
export interface ConsumerPacksOpRequest extends BaseRequest {
  op: "consumerPacks";
}

/** policy.yaml `protect:` for the launcher. Result: `{ paths: string[] }`. */
export interface ProtectPathsOpRequest extends BaseRequest {
  op: "protectPaths";
}

/** What the launcher's object twins hide beyond the confined files
 *  (confidentiality-plan-14 §8.1, §8.2): the law's blob locks above `public`
 *  and the human labels (policy.yaml `paths:` and the dashboard's), so a
 *  labelled path that no longer exists in a repository's work tree still has
 *  its history hidden. Read-only, data plane: the same law `policyDocument`
 *  and `pathLevels` already answer. Result: {@link GitHistoryLocksResult}. */
export interface GitHistoryLocksOpRequest extends BaseRequest {
  op: "gitHistoryLocks";
  /** Plan 14 §11.1 R1: the caller's workspace (a launch's), at most 16
   *  absolute paths. Each is registered with the known-repository registry
   *  (source `launch`: the work tree it lies in, by real path; data-plane
   *  cap), resolved first, and listed in `repos` once resolved even when it
   *  holds no labelled version. */
  roots?: string[];
}

export interface GitHistoryLocksResult {
  /** The confidentiality axis; OFF answers empty lists. */
  axis: boolean;
  /** policy.yaml `blobs:` above `public`: `sha1:<40 hex>` / `sha256:<64 hex>`. */
  blobs: Array<{ id: string; level: string }>;
  /** Every human label, EVERY level (a `public` label is a carve-out the
   *  launcher's precedence needs): a literal as its normalized absolute
   *  path, a pattern as compiled (`~` expanded; `**` + "/…" when unrooted). */
  labels: Array<{ path: string; level: string; recursive: boolean; glob?: true }>;
  /** Plan 14 §11.1 R2: the GLOBAL LOCKED SET, bare hex names per object
   *  format: every known repository's labelled versions (gone paths and
   *  patterns resolved to blob ids) and the `blobs:` locks above `public`.
   *  Axis OFF: empty. */
  lockedSet: { sha1: string[]; sha256: string[] };
  /** The known repositories resolved under the labels in force that hold a
   *  labelled version (and each `roots` repository once resolved, even with
   *  none): `key` is the resolution key (launcher history-labels.ts
   *  `resolutionKey`), `blobs` the labelled versions (history and index). */
  repos: Array<{ root: string; format: "sha1" | "sha256"; key: string; blobs: string[] }>;
  /** Every known repository is resolved under the labels in force. */
  complete: boolean;
  /** The known repositories that are not (not yet, a failed attempt, over
   *  a cap). Their earlier versions stay in `lockedSet`. */
  pending: string[];
  /** Plan 14 §11.1 R3: the known repositories whose sanitized copies (every
   *  pack holding an id of `lockedSet`, rebuilt without them) were present
   *  and sealed in the current epoch at the last preparation cycle. A hint:
   *  the launcher recomputes each pack's exclusion and checks the seals
   *  itself, and binds only what passes. Absent when preparation is off. */
  prepared?: Array<{ root: string; format: "sha1" | "sha256" }>;
  /** Plan 14 §11.1 R3: the preparation's state, for the doctor (names and
   *  counts, never a value). Absent when preparation is off. */
  preparation?: {
    ready: number;
    pending: string[];
    capped: Array<{ root: string; reason: string }>;
    failed: Array<{ root: string; reason: string }>;
    /** Set while nothing is built: why (an unconfined period is live). */
    paused?: string;
    /** Source bytes the kept copies stand for. */
    bytes: number;
    caps: { cycleBytes: number; totalBytes: number };
    /** The last cycle's end (ms since the epoch), or null before the first. */
    at: number | null;
  };
}

/** Plan 14 §11.1 R1: add a repository to the known-repository registry
 *  (source `register`). DATA plane, add-only: the root must be a git work
 *  tree the arbiter can read (validated by hardened git), outside Mandu's
 *  own home; at most 256 data-plane roots (a full registry refuses, never
 *  evicts). Asynchronous: a socket call runs it. Axis OFF: nothing is
 *  registered. Result: {@link RegisterRepositoryResult}. */
export interface RegisterRepositoryOpRequest extends BaseRequest {
  op: "registerRepository";
  /** An absolute path in the work tree (its top is registered). */
  root: string;
}

export interface RegisterRepositoryResult {
  axis: boolean;
  /** The work-tree root registered (real path); null with the axis OFF. */
  root: string | null;
  /** False when it was already known (renewed) or the axis is OFF. */
  added: boolean;
  /** Repositories the registry knows. */
  known: number;
}

// ── Enforcement-cache seals and epochs (confidentiality-plan-14 §11.2) ──────
//
// HUMAN PLANE, all four (arbiter-human-plane.md; `HUMAN_PLANE_OPS`): on the
// data socket an agent in `secrets` mode could re-seal a cache file planted
// during an earlier unconfined period (it knows the hash: it wrote the
// file), and could hold every seal void with a fake live launch. The
// launcher dials the human socket; the arbiter's own scan cache uses the
// store in-process (policy/cache-seals.ts).

/** The current epoch's seals for `keys` of `kind`. Answers none while no
 *  seal is honoured (an unconfined launch is live, or the confidentiality
 *  axis is off). Result: {@link CacheSealsResult}. */
export interface CacheSealsOpRequest extends BaseRequest {
  op: "cacheSeals";
  /** `object-twin` | `history-walk` | `history-scan`, or any other
   *  `[a-z][a-z0-9-]*` kind (at most 41 characters). */
  kind: string;
  /** At most 10,000 keys, each `[A-Za-z0-9][A-Za-z0-9._/-]*` (at most 256). */
  keys: string[];
}

export interface CacheSealsResult {
  epoch: string;
  honoured: boolean;
  /** Why not honoured. */
  reason?: string;
  /** When live unconfined launches are why: the oldest five, so the launch
   *  that finds the caches void can name them (plan 14 §11.2.1). Display
   *  only; absent from an older arbiter. */
  live?: Array<{ pid: number; mode: string; posture: string; walled: boolean; session?: string; begunAt?: number; workspace?: string; why?: string }>;
  /** Why the current epoch began, when honoured: `unprotected-ended`,
   *  `unclean-stop` or `first-start` (policy/cache-seals.ts `EpochCause`).
   *  Display only: a launch rebuilding entries this epoch has no seal for
   *  says why (plan 14 §11.2.1). Absent from an older arbiter. */
  epochCause?: "unprotected-ended" | "unclean-stop" | "first-start";
  seals: Array<{ key: string; sha256: string; size: number }>;
}

/** Record seals for cache entries just written (or just verified: the seal
 *  is refreshed) in the current epoch, and report the entries a reader did
 *  not use (an event names each kind and key; no content). Add-only.
 *  Result: {@link SealCacheEntriesResult}. */
export interface SealCacheEntriesOpRequest extends BaseRequest {
  op: "sealCacheEntries";
  entries: Array<{ kind: string; key: string; sha256: string; size: number }>;
  rejected?: Array<{ kind: string; key: string; reason: "unsealed" | "mismatch" }>;
}

export interface SealCacheEntriesResult {
  epoch: string;
  recorded: number;
}

/** A launch starts, before its agent does. The arbiter classifies it (fail
 *  closed: confined only as `secrets`/`full` with the Mandu home
 *  write-protected, under this arbiter's confidentiality axis, at the
 *  `confined` posture, or at the `read-blocked` posture with `homeSealed`);
 *  an unconfined launch holds every seal void until it ends. Result:
 *  {@link BeginLaunchResult}. */
export interface BeginLaunchOpRequest extends BaseRequest {
  op: "beginLaunch";
  /** The launcher's pid: an unconfined launch ends when it is gone. */
  pid: number;
  mode: string;
  posture: string;
  writeProtect: boolean;
  /** macOS (posture `read-blocked`): the launch's one Seatbelt profile
   *  denies everything under it every direct read and write of the Mandu
   *  home (policy/cache-seals.ts `LaunchClaim.homeSealed`). The
   *  confidentiality.md §7.3 residual remains: code a system service runs
   *  for the agent outside the profile (plan 14 §11.2 residual (e)). Only
   *  `true` counts, and only beside `read-blocked`. */
  homeSealed?: boolean;
  /** The agent's world cannot reach the human-plane socket (the guard's
   *  `unixDeny`, or the wrap's tmpfs over its directory). Absent (an older
   *  launcher) counts as false: while an unwalled launch is live the human
   *  socket's guard and proxy records are claims (plan 13 D9 leftovers). */
  humanPlaneWalled?: boolean;
  /** The launch's session (the launcher's scope id): display only, so the
   *  exposure can name it (`humanPlaneStatus`). A value not shaped like a
   *  scope id is dropped. */
  sessionId?: string;
  /** The launch's HOME (what its agent gets as `$HOME`), with `sessionId`:
   *  the catalog's `~` places for that session's opens (`decideSecretOpen`
   *  judges against it as well as the arbiter's own HOME; plan 10 §11.13,
   *  2026-10-17). Recorded only from an attested request; not an absolute
   *  path of at most 4096 bytes without a control character: dropped. */
  home?: string;
  /** The launch's workspace (its working directory): display only, so a
   *  launch that finds the caches void while this one runs can name it
   *  (plan 14 §11.2.1). Not an absolute path of at most 512 characters
   *  without a control character: dropped. */
  workspace?: string;
}

export interface BeginLaunchResult {
  /** Handed back to `endLaunch`. */
  token: string;
  confined: boolean;
  epoch: string;
  /** The unconfined launches live before this one (absent from an older
   *  arbiter): a confined launch warns of them. */
  others?: Array<{ pid: number; mode: string; posture: string; walled: boolean; session?: string; begunAt?: number; workspace?: string; why?: string }>;
}

/** HUMAN PLANE, read-only (arbiter-human-plane.md §10.1.1): is the human
 *  plane exposed now (a launch whose agent can reach the human socket is
 *  live), since when, and by which launches. It decides nothing: the
 *  confined launches' launchers poll it to tell their user why their guard
 *  is not believed, and the dashboard shows it. Result:
 *  {@link HumanPlaneStatusResult}. */
export interface HumanPlaneStatusOpRequest extends BaseRequest {
  op: "humanPlaneStatus";
}

export interface HumanPlaneStatusResult {
  /** true while a launch with no wall is live: the human socket's guard and
   *  proxy reports are claims (§10.1). A store that cannot answer counts as
   *  exposed (fail closed), with one launch of pid 0. */
  exposed: boolean;
  /** When this arbiter first saw the current exposure (ms since the epoch);
   *  null while walled. */
  since: number | null;
  /** The unwalled launches live now, oldest first. */
  launches: Array<{ pid: number; mode: string; posture: string; session?: string; begunAt?: number }>;
}

/** A launch ended; an unconfined one's end starts a new epoch. Result:
 *  {@link EndLaunchResult}. */
export interface EndLaunchOpRequest extends BaseRequest {
  op: "endLaunch";
  token: string;
}

export interface EndLaunchResult {
  ended: boolean;
  rotated: boolean;
  epoch: string;
}

/** policy.yaml `unix_sockets:`, `write_protect:` and `remote_mounts:` for
 *  the launcher (guard-settings.ts), as written (`~` unexpanded). Result:
 *  {@link GuardSettingsResult}. Read-only. */
export interface GuardSettingsOpRequest extends BaseRequest {
  op: "guardSettings";
}

export interface GuardSettingsResult {
  unixAllow: string[];
  writeProtect: { deny: string[]; ask: string[]; unprotect: string[] };
  /** `remote_mounts.trust_lookups` (plan 13 §4.9). Absent from an older
   *  arbiter: none trusted. */
  trustLookups?: { mount: string; type: string }[];
}

/** Verify a session log's hash chain. Result: `{ ok, chained, unchained, brokenAt?, head }`. */
export interface VerifyEventsOpRequest extends BaseRequest {
  op: "verifyEvents";
  sessionId: string;
}

/** Plan 13 D8 (2026-10-03): what this arbiter knows a binary to be, judged
 *  as every reader list judges it: by its name and path and by the hashes of
 *  the host's installed printers and code-running programs. The guard asks
 *  it for a secret socket's reader (the ssh-agent). Read-only. Result:
 *  `ReaderProgramOpResult`. */
export interface ReaderProgramOpRequest extends BaseRequest {
  op: "readerProgram";
  /** The resolved executable. */
  exe: string;
  /** sha256 of the inode it runs, hex. */
  sha256?: string;
}

export interface ReaderProgramOpResult {
  /** A printer, by name or path or as a byte-identical copy of one (`binaryPrints`). */
  prints: boolean;
  /** A program that runs code it is given, likewise (`binaryRunsCode`). */
  runsCode: boolean;
  /** The installed program a renamed copy is byte for byte (`renamedCopyOf`), else null. */
  copyOf: string | null;
}

/** policy.yaml `ssh_agent.readers` for the launcher. Result: `{ readers: unknown[] | null }`. */
export interface SshAgentPolicyOpRequest extends BaseRequest {
  op: "sshAgentPolicy";
}
export interface EnvSourceWire {
  name: string;
  source: string;
  bindings: string[];
}

export interface WhyHostOpRequest extends BaseRequest {
  op: "whyHost";
  host: string;
}

/** `mandu why <symbol>` (confidentiality-plan-15 §13.8): where a `$MDU:`
 * placeholder came from; for a prompt finding, its filter, category,
 * action, hold, session and turn, the verdicts on file and the policy now.
 * HUMAN PLANE (it reads the session events); never a value. Result:
 * `WhySymbolOpResult` (prompt-filter/why-symbol.ts). */
export interface WhySymbolOpRequest extends BaseRequest {
  op: "whySymbol";
  symbol: string;
  /** A session to search first (the symbol's own is searched anyway). */
  session?: string;
}

/** Fetch the active inbound/outbound/origin policy rules, serialized for the
 * dashboard's per-tool-call policy modal. OBSERVABILITY ONLY — decides nothing;
 * mirrors the specs the gate enforces. */
export interface PolicySnapshotOpRequest extends BaseRequest {
  op: "policySnapshot";
}

// ── Egress-approval queue ─────────────────────────────────────────────────────

/** List queued egress-approval entries, optionally filtered by status. */
export interface EgressApprovalsRequest extends BaseRequest {
  op: "egressApprovals";
  /** Only entries with this status (pending/approved/denied). Absent → all. */
  status?: ApprovalStatus;
}

/** Set a human verdict (approve/deny) on a queued egress-approval entry.
 *
 * NOTE: the entry id is carried as `approvalId`, NOT `id` — `id` is the reserved
 * BaseRequest correlation field, and naming a payload field `id` would clobber it
 * over the wire (same reason RecordToolCallRequest uses `toolUseId`). */
export interface ResolveEgressApprovalRequest extends BaseRequest {
  op: "resolveEgressApproval";
  /** The entry id (from an earlier egressApprovals/pending entry). */
  approvalId: string;
  /** true → "approved"; false → "denied". */
  approve: boolean;
  /** Verdict scope: "always" (standing, never expires — the default, and the
   * behavior of every pre-scope caller) or "once" (satisfies exactly one gated
   * decision, then the pair re-queues on its next attempt). */
  scope?: ApprovalScope;
  /** "Send without it" (confidentiality.md §4): with `approve: false`, a
   * one-shot denial whose use forwards the next such request with a marker
   * in the symbol's place. Taken only on a row the listing marks
   * `stripOffered` (a secret's symbol × a network host); refused on any
   * other row, and with `approve: true`. Absent or false: the old answer. */
  strip?: boolean;
}

/** Forget a human verdict on an egress-approval entry (dashboard.md §4.25):
 * the entry is deleted, so the pair's next attempt asks again. Admin-only.
 * Refused for an unknown or still-pending id. `approvalId`, not `id`, for the
 * same wire reason as {@link ResolveEgressApprovalRequest}. */
export interface ForgetEgressApprovalRequest extends BaseRequest {
  op: "forgetEgressApproval";
  approvalId: string;
}

/** Set the arbiter's GLOBAL egress posture. TIGHTEN-ONLY BY DEFAULT
 * (siem-integration.md §4.3, scenario D): a Wazuh active-response callback
 * TIGHTENS the posture, and a SIEM rule may raise it (normal → lockdown) but
 * never lower it — a loosen without `allowRelax` is a refused no-op. The
 * human-driven route (the dashboard Protection drawer, policy-surface.md §9
 * §8.6) sends the explicit `allowRelax` flag to apply a loosen, audited
 * identically. Scope is GLOBAL today (the egress gate carries no sessionId);
 * a real `sessionId` other than `*`/`global` is refused, not silently stored. */
export interface SetSessionPostureRequest extends BaseRequest {
  op: "setSessionPosture";
  /** The target posture ("lockdown" to engage; "normal" loosens only when
   *  `allowRelax` is set, else it is a refused no-op). */
  posture: string;
  /** Omit / `*` / `global` for the campaign-wide lockdown. Any other value is
   *  refused until per-session enforcement is wired at the egress gate. */
  sessionId?: string;
  /** Free-text provenance for the audit event (e.g. the Wazuh rule id/alert). */
  requestedBy?: string;
  /** Explicit relax opt-in (policy-surface.md §9.8.6 — the dashboard's
   *  human-driven ▶ Resume). A loosen WITHOUT it stays a refused no-op
   *  (`applied: false`) — the tighten-only default is intact, so the SIEM
   *  actuator and any legacy caller are unchanged. WITH it, the loosen applies
   *  and is audited through the same `posture_change` event as a tighten.
   *  Additive/back-compat: absent ⇒ false. */
  allowRelax?: boolean;
}

/** Bind a SESSION to an inbound/outbound trust spec (agent-e2e-harness.md
 * §7.1 — one arbiter serving MIXED agents). The binding is keyed by the same
 * session identity the proxies thread into `classify`/`symbolize`
 * (MANDU_SESSION_KEY / the launcher scopeId); classification for that
 * session then resolves tool names against the bound agent's spec instead of
 * the process-global boot spec. FAIL-CLOSED: an unknown `spec` value binds the
 * "fail-closed" empty spec (every tool UNTRUSTED) rather than being ignored —
 * the caller declared "this session is agent X" and the arbiter could not
 * honor it, so the session must not inherit another agent's TRUSTED grants.
 * In-memory only; after an arbiter restart the session falls back to the
 * global spec (over-symbolizing for foreign tool names — safe). */
export interface SetSessionSpecRequest extends BaseRequest {
  op: "setSessionSpec";
  /** The session identity future classify/symbolize calls will carry. */
  sessionKey: string;
  /** An InboundSpecId ("claude-code" | "openclaw-agent" | "opencode" | …). */
  spec: string;
  /** Free-text provenance for the log (e.g. "launcher --target opencode"). */
  requestedBy?: string;
}

// ── Reply row reservation (docs/design/ui/reply-row-reservation.md §3.3, §3.6) ──

/** The line count of the value behind ONE symbol token, so the proxy can
 * reserve that many rows for the reply filter to paint — never the value.
 * Resolves DEEPLY, as `desymbolize` does (nested chains and `.field` paths;
 * a Markdown-escaped token is unescaped first). Result: `{ lines }` after
 * dropping one trailing line break, or null for anything that is not exactly
 * one known symbol token. Served with the same channel exposure as
 * `desymbolize` (§5.3).
 *
 * v2 (§11.5): with `width` (an integer 20..1000, the content width `W`) the
 * result also carries `rows`, the length of `layoutRows(value, width, first
 * ?? width)` on the same deep-resolved value. `first` is 0 or an integer
 * ⌈width/2⌉..width, and requires `width`. Anything else is refused
 * (`ok:false`), never clamped. `rule` (§17) is the TUI's wrap rule the rows
 * are counted by: `ink` (the default) or `terminal`; it requires `width`.
 * `indent` (§11.2) is the terminal column the content area starts at (the
 * relay's columns minus `width`), an integer 0..10000 that requires
 * `width`: a TAB in the value reaches the terminal's own tab stop, as on
 * the screen. Absent: 0. */
export interface SymbolShapeRequest extends BaseRequest {
  op: "symbolShape";
  token: string;
  width?: number;
  first?: number;
  rule?: ReplyLayoutRule;
  indent?: number;
}

/** The wrap rule a TUI lays its reply out by (reply-row-reservation.md §17;
 * reserve-layout.ts LayoutRule): `ink`, word wrap (Claude Code, Codex), or
 * `terminal`, the terminal's own autowrap at the full width (Goose). */
export type ReplyLayoutRule = "ink" | "terminal";

/** How the reply filter relays the session's output (reply-filter `relay_mode`). */
export type SessionRelayMode = "pty" | "pipe" | "passthrough";

/** The reply filter reports its relay mode (and again on resize). In memory,
 * keyed by the session key the proxy shares (MANDU_SCOPE_ID =
 * MANDU_SESSION_KEY). NOT bind-once: a missing entry only means no
 * expansion. `reserve` says the filter can paint reserve blocks; `wrap` says
 * it paints v2 (`T/1:N:W:F`) heads (absent: a v1 filter). `cols`/`rows` are
 * positive integers ≤ 10000; `cols` sets the proxy's wrap width `W`. HUMAN
 * PLANE ONLY (§11.5): an agent that could set `cols` could replay a secret at
 * widths of its choosing and read its line lengths off the row counts.
 * `rule` (§17): the agent's TUI wraps its reply by the terminal's autowrap
 * (`terminal`, Goose) or by word wrap (`ink`, the default when absent). */
export interface SetSessionRelayRequest extends BaseRequest {
  op: "setSessionRelay";
  sessionKey: string;
  mode: SessionRelayMode;
  reserve: boolean;
  cols?: number;
  rows?: number;
  wrap?: boolean;
  rule?: ReplyLayoutRule;
}

/** Read a session's relay state (null when never reported). Human plane only. */
export interface SessionRelayOpRequest extends BaseRequest {
  op: "sessionRelay";
  sessionKey: string;
}

/** The proxy records a reserve block it expanded (reply-row-reservation.md
 * §3.8): `token` is exactly one symbol token (the head's), `n` its rows
 * (2..200), and for a v2 head `width`/`first` (together, the §11.3 ranges).
 * Stored in memory per session under the token's hash, so the reply filter
 * can lay out a continuation row `$MDU/<hash>/<i>` whose head it never saw.
 * Tokens and counts only. HUMAN PLANE ONLY. */
export interface NoteReserveBlockRequest extends BaseRequest {
  op: "noteReserveBlock";
  sessionKey: string;
  token: string;
  n: number;
  width?: number;
  first?: number;
}

/** Read a block back by the hash its continuation rows carry: `{ token, n,
 * width?, first? }`, or null when none was noted. HUMAN PLANE ONLY. */
export interface ReserveBlockOpRequest extends BaseRequest {
  op: "reserveBlock";
  sessionKey: string;
  hash: string;
}

/** `reserveBlock`'s answer (null when no block was noted for the hash). */
export interface ReserveBlockWire {
  token: string;
  n: number;
  width?: number;
  first?: number;
}

// ── The after-the-fact note across a resume ──────────────────────────────────

/** A model proxy records the tool-call ids whose result body it forwarded
 * to the model in clear (confidentiality.md §7.1, "Masked after the fact").
 * Ids only (1..256 printable ASCII each, at most 10 000 per request; others
 * are skipped), kept in mandu.db so a conversation resumed under a new launch
 * gets its note. HUMAN PLANE ONLY. */
export interface RecordForwardedClearRequest extends BaseRequest {
  op: "recordForwardedClear";
  ids: string[];
}

/** `recordForwardedClear`'s answer: how many ids were new, how many skipped. */
export interface RecordForwardedClearResult {
  recorded: number;
  skipped: number;
}

/** Which of `ids` were recorded by `recordForwardedClear` (at most 10 000).
 * HUMAN PLANE ONLY.
 *
 * "Two launches at once" (2026-10-17): `since`, the `generation` of the
 * proxy's previous answer, also asks for the ids recorded after it
 * (`recent`), so a proxy re-learns an id it holds as unknown once another
 * launch's proxy records it, in the same one op per request. */
export interface ForwardedClearRequest extends BaseRequest {
  op: "forwardedClear";
  ids: string[];
  since?: number;
}

/** `forwardedClear`'s answer: the recorded subset, in the order asked; the
 * store's generation; with `since`, the ids recorded after it (oldest first,
 * at most 10 000; `recentComplete` false when more were). */
export interface ForwardedClearResult {
  ids: string[];
  generation?: number;
  recent?: string[];
  recentComplete?: boolean;
}

/** One result's placeholder record (symbol-table/forwarded-placeholders.ts):
 * `[offset, token]` pairs, offsets in UTF-16 code units of the text the proxy
 * forwarded, each token exactly one symbol token, and the proxy's SHA-256 of
 * the call id and that text (64 lowercase hex digits). */
export interface ForwardedPlaceholderMapWire {
  callId: string;
  digest: string;
  placeholders: Array<[number, string]>;
}

/** A model proxy records, for results it forwarded in clear in an OpenClaw
 * session, where Mandu's placeholders sat in each and its digest
 * (confidentiality.md §6, *Across a relaunch*). At most 1 000 maps per
 * request; a malformed one is skipped. HUMAN PLANE ONLY. */
export interface RecordForwardedPlaceholdersRequest extends BaseRequest {
  op: "recordForwardedPlaceholders";
  maps: ForwardedPlaceholderMapWire[];
}

/** `recordForwardedPlaceholders`'s answer: how many were recorded, skipped. */
export interface RecordForwardedPlaceholdersResult {
  recorded: number;
  skipped: number;
}

/** The records of `ids` (at most 10 000). HUMAN PLANE ONLY. */
export interface ForwardedPlaceholdersRequest extends BaseRequest {
  op: "forwardedPlaceholders";
  ids: string[];
}

/** `forwardedPlaceholders`'s answer: the recorded maps, in the order asked. */
export interface ForwardedPlaceholdersResult {
  maps: ForwardedPlaceholderMapWire[];
}

// ── Observability event stream ────────────────────────────────────────────────

/** Append one opaque observability event. `event.sessionId` and `event.id` are
 * required; the arbiter assigns the per-session monotonic `seq`. */
export interface EmitRequest extends BaseRequest {
  op: "emit";
  /** Opaque JSON event (structurally a dashboard ManduEvent). The arbiter reads
   * only `sessionId`/`id` (+ `ts` for summaries) and assigns `seq`. */
  event: ArbiterEvent;
}

/** Read persisted events for a session with seq > sinceSeq (default 0). */
export interface EventsRequest extends BaseRequest {
  op: "events";
  sessionId: string;
  /** Return only events with seq strictly greater than this. Default 0 (all). */
  sinceSeq?: number;
}

/** List known sessions with counts + ts bounds. */
export interface SessionsRequest extends BaseRequest {
  op: "sessions";
}

/** Delete ONE session's event log (observability only — the dashboard's
 * sidebar delete; any session, live or test). An unknown session (no log file)
 * is an error response, never a silent success; a traversal-shaped id is
 * rejected by the store's safe-session-id guard. */
export interface DeleteSessionRequest extends BaseRequest {
  op: "deleteSession";
  sessionId: string;
}

/** Subscribe to a session's live event feed on a DEDICATED connection. The
 * arbiter first replays the backlog (events since sinceSeq), then pushes each
 * newly-emitted event. Monopolizes the connection until the client closes it. */
export interface SubscribeRequest extends BaseRequest {
  op: "subscribe";
  sessionId: string;
  /** Replay backlog with seq > sinceSeq before streaming live. Default 0 (all). */
  sinceSeq?: number;
}

// ── Provenance (taint) registry ──────────────────────────────────────────────

/** Mark a process as tainted by untrusted network input. */
export interface TaintProcessOpRequest extends BaseRequest {
  op: "taintProcess";
  procKey: string;
  originHost: string;
  session?: string;
}

/** Record a parent→child process lineage edge. */
export interface ProcessLineageOpRequest extends BaseRequest {
  op: "processLineage";
  childKey: string;
  parentKey: string;
  session?: string;
}

/** Confidentiality plan 13 §9 R1 (and D2): `procKey` received the bytes of
 *  `flowsFrom` through a descriptor (a pipe, a FIFO, a socket pair end, a
 *  connection to a holder's listener), as the guard found it. Recorded as
 *  flows (never lineage edges) that every taint walk follows, the model
 *  exit's fold included. Only adds taint: from the data socket, a claim. */
export interface RecordProcessFlowOpRequest extends BaseRequest {
  op: "recordProcessFlow";
  procKey: string;
  flowsFrom: string[];
  session?: string;
}

/** Confidentiality plan 13 §4.5.1 (decision 2026-10-02): the AGENT process
 *  itself holds `channel` (its socket, `socket:[ino]`), the other end of a
 *  connection a holder (`flowsFrom`) accepted or held at its taint: what the
 *  holder writes reaches the agent, which is never made a holder (D2). The
 *  guard records it before the holder gets the connection; `closed: true`
 *  when it sees the agent no longer hold the channel. A tool result the agent
 *  itself produced in a call whose window overlaps the flow is masked at the
 *  holders' level (`agentReceiptTaint`). An open from the data socket is a
 *  claim (it only adds masking); a close from it is not recorded. */
export interface RecordAgentFlowOpRequest extends BaseRequest {
  op: "recordAgentFlow";
  /** The agent's end: `socket:[ino]`, or (2026-10-02) the path of a FIFO
   *  the agent reads (a file-like channel, which a file tool's result counts). */
  channel: string;
  /** The holders (open): their proc keys. Ignored for a close. */
  flowsFrom?: string[];
  closed?: boolean;
  session?: string;
}

/** Confidentiality plan 13 §4.5.1: for each tool result of a request, the
 *  level the agent's own connections to a holder mask it at (null: none).
 *  Answered only for a tool whose result the agent itself produces (not a
 *  shell's output, `execOutput`, which its process tree's fold answers; not
 *  a harness-local tool; `agent-receipt.ts`); a file tool (`paths`) only by
 *  a flow on a file-like channel, a named pipe a holder writes that the
 *  agent read itself (2026-10-02).
 *  From the human socket the first ask of each call ends its window; from
 *  the data socket it is read-only. */
export interface AgentReceiptTaintOpRequest extends BaseRequest {
  op: "agentReceiptTaint";
  calls: Array<{ callId: string; tool: string }>;
  session?: string;
}

export interface AgentReceiptTaintResultWire {
  calls: Array<{
    callId: string;
    /** The strictest level the holders hold; null = not masked by this leg. */
    level: string | null;
    files: string[];
    apps: string[];
    /** The call's relay was never recorded: every flow before its result
     *  counted (fail-closed). */
    unattributed?: boolean;
  }>;
}

/** Query whether a process (or any ancestor) is network-tainted. */
export interface IsProcessTaintedOpRequest extends BaseRequest {
  op: "isProcessTainted";
  procKey: string;
}

/** Mark a file (by content hash + path) as written by a tainted process. */
export interface TaintFileOpRequest extends BaseRequest {
  op: "taintFile";
  contentHash: string;
  path: string;
  originHost: string;
  writerProc?: string;
  session?: string;
}

/** Query whether a file (by content hash or path) is tainted. */
export interface FileTrustOpRequest extends BaseRequest {
  op: "fileTrust";
  contentHash?: string;
  path?: string;
}

// ── Plan 10: confidentiality taint of processes (flow-based confinement) ────

/** A process opened a secret file RAW as a listed reader (plan 10 §3.1). */
export interface TaintProcessSecretOpRequest extends BaseRequest {
  op: "taintProcessSecret";
  procKey: string;
  path: string;
  level: string;
  app: string;
  session?: string;
}

/** The secret taint of a process and its ancestors. */
export interface ProcessSecretTaintOpRequest extends BaseRequest {
  op: "processSecretTaint";
  procKey: string;
}

/** The root process of a tool call (plan 10 §4.2). */
export interface RecordCallRootOpRequest extends BaseRequest {
  op: "recordCallRoot";
  callId: string;
  procKey: string;
  session?: string;
}

/** The fold over a tool call's tree: level, the files behind it, and the
 * output rule the proxy applies (plan 10 §3.2, §4.2). */
export interface CallTaintOpRequest extends BaseRequest {
  op: "callTaint";
  callId: string;
  /** The tool call's command text as the agent echoed it (Bash.command).
   * Plan 13 D9 follow-up: NOT what the call is bound by (that is the command
   * the proxy recorded, `execGate` / `recordCallCommand`); it names only the
   * most-recent-exec guess, which is folded and never lowers a mask. */
  command?: string;
  session?: string;
  /** The tool result's text, for the exec-twin tests (plan 10 §11.8: the
   * structured twin, a document's whole-file twin, a key listing
   * of a structured twin, and a folder's names). Absent ⇒ the answer
   * carries no `twinOf`. */
  output?: string;
  /** Plan 10 §11.8 (review of !1604): `output` is a Codex exec result, whose
   * FIRST head Codex wrote before the program's output (the openai-proxy says
   * so). The twin tests look through that one head (bounded digits) and no
   * other; absent, no head is stripped, since any head in the text is the
   * program's own (a forged head's digits were a channel). */
  codexHead?: boolean;
  /** Plan 10 §11.12, the unmapped-command backstop: the call is to this
   * tool, which the proxy's gate surface does not know as a shell but whose
   * input carries a command-like field (`command`). The arbiter answers only
   * when the confidentiality axis is on and the session's inbound spec has
   * no entry for the tool (an empty answer otherwise); a call the guard
   * never tied to a process tree is answered from the session's raw secret
   * reads (`evidence: "session"`). */
  unmappedTool?: string;
  /** Plan 10 §11.18: the proxy names `unmappedTool` one of its agent's own
   *  built-ins that no inbound spec carries (the openai-proxy's
   *  CODEX_MAPPED_TOOLS, or a cell / poll it identified): it has a mapping,
   *  so it is never masked for having none, and keeps the rules below. */
  builtin?: boolean;
  /** Plan 13 D7, a background poll tied to its call (2026-10-09): this ask
   *  is for the poll whose tool_use id this is, which the proxy tied to the
   *  call `callId` started (the anthropic-proxy's `claudeBackgroundPolls`).
   *  From the human socket the arbiter remembers that the poll continues
   *  that call, so a symbol minted for the poll's output (call id: the
   *  poll's) counts in the value backstop when that call's tree held a
   *  secret. Only adds masking; ignored from the data socket. */
  forPoll?: string;
}

/** Plan 10 §11.13 (HUMAN PLANE): the stdio MCP servers the launched agent is
 *  configured with, as the launcher read them from the agent's own config
 *  before the agent started. The arbiter finds each server's process by the
 *  argv the agent spawns it with (the guard's exec records). Accepted only on
 *  the human socket: from the data socket the agent world could name a
 *  process of its choosing as a server. */
export interface RegisterMcpServersOpRequest extends BaseRequest {
  op: "registerMcpServers";
  sessionKey: string;
  servers: Array<{ name: string; command: string; args: string[] }>;
  /** Every file the launcher's read consulted (present or not), each with
   *  the stamp it had when read (`mcpSourceStamp`: inode, size, mtime, or
   *  `absent`). The latest registration's list replaces the session's
   *  previous one. While any of them differs from its stamp (the config
   *  changed after the read, and the launcher's re-read has not landed yet),
   *  no server of the session is `clean`: a process the old config names
   *  cannot vouch for a server the new config may run (plan 10 §11.17).
   *  Absent: no check (a registration from a launcher that predates it). */
  sources?: Array<{ path: string; stamp: string }>;
}

/** Plan 10 §11.13.1 (HUMAN PLANE): this session's egress proxy terminates
 *  TLS (the launch minted its CA and exported it with `HTTPS_PROXY`), so a
 *  registry token's symbol sent by npm is put back at its bound registry,
 *  and npm can be served the `.npmrc` twin instead of the raw file. Accepted
 *  only on the human socket: the launcher knows the proxy's posture, the
 *  agent world does not get to claim it. */
export interface RegisterWireReleaseOpRequest extends BaseRequest {
  op: "registerWireRelease";
  sessionKey: string;
  /** The session's proxy inspects TLS (MITM on). false clears the session. */
  inspecting: boolean;
  /** The session's `NO_PROXY` entries: npm reaches these around the proxy,
   *  so a token bound to one of them is not servable. */
  direct?: string[];
  /** The launcher's pid: with it the word is also kept across an arbiter
   *  restart while that launcher runs (wire-release-sessions.ts), and an
   *  `inspecting: false` drops only that launcher's word. */
  pid?: number;
}

/** Agent-sign-in.md §3 (HUMAN PLANE): a field of the agent's own key file
 *  (Goose's `secrets.yaml`) authenticates to a host, the provider the launch
 *  routes. The field is bound there (current-bindings.ts rule 1), so the
 *  model proxy may put the key back in the auth header of a request to that
 *  host. Accepted only on the human socket: from the data socket the agent
 *  could bind its key to a host of its own. In memory for the arbiter's
 *  life, and across a restart while the launcher named by `pid` lives.
 *  Answers `{granted}`. */
export interface RegisterAuthGrantOpRequest extends BaseRequest {
  op: "registerAuthGrant";
  /** The key file's absolute path (exclusive with `env`). */
  path?: string;
  /** The environment form (agent-sign-in.md §3.8): the variable holding the
   *  agent's key (`ANTHROPIC_API_KEY`); its row is `env:NAME`, and each
   *  grant's `field` must be NAME. Exclusive with `path`. */
  env?: string;
  /** One per field: a plain host (no port), and whether the upstream is
   *  https (plain HTTP is granted only to a loopback host). */
  grants: Array<{ field: string; host: string; https: boolean }>;
  /** The launcher's pid: the grant is then also kept in mandu.db, and a
   *  restarted arbiter takes it back while that process lives (§3.2 item
   *  4). Absent: memory only. */
  pid?: number;
}

/** Plan 10 §11.13: is the MCP server behind this tool tainted? */
export interface McpServerTaintOpRequest extends BaseRequest {
  op: "mcpServerTaint";
  /** The tool as the agent names it: `mcp__<server>__<tool>`. */
  tool: string;
  sessionKey?: string;
}

/** The answer. `tainted`: some process the server's name maps to has a
 *  tree that read a secret raw (the fields describe it). `clean`: the name
 *  maps to EXACTLY one process and its tree read none. `unmapped`: the
 *  server was not registered, matches no process, the confidentiality axis
 *  is off, or the tool is ambiguous (each proxy keeps its older rule).
 *  `own`: one of Mandu's own tools (inspect, declassify, policy). */
export interface McpServerTaintResultWire {
  verdict: "tainted" | "clean" | "unmapped" | "own";
  /** The registered server name the tool matched, when any. */
  server?: string;
  /** How many processes the name maps to. */
  candidates: number;
  /** True when a server that would be `clean` is answered `unmapped`
   *  because a config file the launcher read changed after that read
   *  (RegisterMcpServersOpRequest.sources). */
  configChanged?: boolean;
  level: string | null;
  files: string[];
  apps: string[];
}

/** Plan 10 §4.2: the guard saw an exec in the agent tree. */
export interface RecordExecRootOpRequest extends BaseRequest {
  op: "recordExecRoot";
  procKey: string;
  parentKey?: string;
  /** Plan 13 D7: the exec'ing process's live ancestor proc keys, nearest
   *  first (`ancestors[0]` is the parent), read before the exec was let go
   *  and stopped below the guard. Every edge is recorded, first edge
   *  winning. Absent: the `parentKey` edge alone. */
  ancestors?: string[];
  argv: string[];
  session?: string;
  /** Plan 13 D7: the exec'ing process is a direct child of the agent (the
   *  guard's `agent_keys`): the shell the agent runs one tool call in, a
   *  candidate root for the call whose command it carries (the call-root
   *  recorder, `ProvenanceStore.callTree`). */
  callRoot?: boolean;
  /** 2026-10-04 (confidentiality.md §6): the exec'ing process's working
   *  directory, as the kernel names it (`/proc/<pid>/cwd`), read while the
   *  exec was suspended. Kept only with `callRoot` and only from the human
   *  plane: the directory a bound call's relative path tokens are read in. */
  cwd?: string;
  /** Plan 13 D7, the orphan subshell: the guard found no agent process among
   *  the actor's live ancestors and names the ORPHAN ROOT above it (the
   *  topmost ancestor, re-parented to a reaper, born after the agent): a tree
   *  whose real parent, a tool call's shell, exited before it acted. Folded
   *  into every call relayed no later than it was first seen. Only widens a
   *  fold, so it is kept from either socket. */
  orphanRoot?: string;
}

/** Confidentiality plan 15 §3.2: the prompt filter. A model-API proxy cuts a
 * request's user-role text into segments tagged by origin and asks what the
 * model may read of each. A PROXY op on the data socket; with `dryRun: true`
 * (the developer dashboard's test bench, §8.1) it is HUMAN-PLANE only: on the
 * data socket a dry run would let the agent's processes test guesses against
 * the registered values without a trace. */
export interface FilterPromptOpRequest extends BaseRequest {
  op: "filterPrompt";
  /** The session key (a minted symbol's session). */
  session?: string;
  /** The agent whose segmenter cut the text: "claude-code", "codex", ... */
  agent: string;
  segments: Array<{ id: string; origin: "human" | "harness" | "side-call"; text: string }>;
  /** Mint nothing, cache nothing (human plane only). */
  dryRun?: boolean;
  /** Plan 15 §7 (phase 3): the caller enacts holds (it waits on a `hold`
   *  answer and asks again). Absent: an `ask` goes with its default (a
   *  proxy that cannot wait, a token count). Holds are filed and verdicts
   *  consulted only for an attested caller (plan 13 D9). */
  holds?: boolean;
  /** The caller's last ask of a held request, its deadline passed (ms
   *  held): no `hold` is answered; a pending ask takes its default. */
  heldMs?: number;
  /** Plan 15 §13.5 item 11: the client understands progress frames
   *  (`{id, progress: true}`, every `FILTER_PROMPT_PROGRESS_MS` while the op
   *  runs), so it can wait for a slow plugin without waiting as long on an
   *  arbiter that never answers. Absent: no frame is sent. */
  progress?: boolean;
}

/** Where an `ask` finding's hold stands (holds.ts). */
export interface PromptHoldStateWire {
  state: "pending" | "sent" | "masked" | "cancelled" | "timed-out" | "default";
  approvalId?: string;
  why?: string;
}

export interface FilterPromptFindingWire {
  start: number;
  end: number;
  category: string;
  filterId: string;
  action: "pass" | "log" | "redact" | "mask" | "ask" | "block";
  symbol?: string;
  how?: "value" | "line" | "merged";
  /** The rule that found it: a pack's pattern id, `keyword`, a key shape. */
  rule?: string;
  /** Phase 3: the span's opaque reference (a keyed hash), on a `human`
   *  segment's finding a human verdict may cover (not a registered value). */
  ref?: string;
  /** Phase 3: a human verdict let this span through as written. */
  let?: "once" | "session";
  /** Phase 3: an `ask` finding's hold. */
  hold?: PromptHoldStateWire;
  /** Next to `ref`: a locked administrator's `ask` row covers the category
   *  (plan 15 §12, 2026-10-04): a verdict covers this message only; a
   *  session answer or a session let-through is refused. */
  onceOnly?: true;
}

export interface FilterPromptSegmentWire {
  id: string;
  origin: "human" | "harness" | "side-call";
  action: "pass" | "rewrite" | "hold" | "block";
  /** `rewrite`: the text the model may read. `block` (phase 2): the same
   *  safe text with each blocked span as `[blocked: <category>]`, which a
   *  proxy may forward only after the human was told; absent when a filter
   *  could not run (nothing of the segment may go). */
  text?: string;
  /** `hold` (phase 3): the Inbox row to wait on and the time left before
   *  the default applies. No `text`: nothing of a held segment goes. */
  hold?: { approvalId: string; timeoutMs: number };
  /** `block`: what the agent shows the human (categories, never a value). */
  reason?: string;
  /** Phase 3: the message's opaque reference (a "let it through, once"
   *  names it), on a `human` segment with a referenced finding; and, for an
   *  attested caller, on a later answer with none to a message that had one
   *  in the session (holds.ts noted messages: a restarted proxy files the
   *  cleared outcome under the message's note, plan 15 §13.7 item 10). */
  turn?: string;
  findings: FilterPromptFindingWire[];
  /** Registered values the prompt floor let through (counted, never named). */
  skipped: number;
  cached: boolean;
}

export interface FilterPromptResultWire {
  segments: FilterPromptSegmentWire[];
  /** False with the confidentiality axis OFF: every finding is `log`. */
  enforcing: boolean;
  dryRun: boolean;
  digest: { policy: string; packs: string; values: string };
}

/** Plan 15 §7 (phase 3): the human's answer to a held prompt. ADMIN-ONLY.
 * `send` = as written, `mask` = the default (mask, or redact without a
 * level), `cancel` = the waiting request is refused (later requests carry the
 * message with the default). `scope`: `once` (this message, default) or
 * `session` (the span in every message of the session). Under a locked
 * administrator's `ask` row `session` is refused with the reason, whatever
 * the answer (plan 15 §12, 2026-10-04): the hold lists `onceOnly`. */
export interface ResolvePromptHoldOpRequest extends BaseRequest {
  op: "resolvePromptHold";
  approvalId: string;
  answer: "send" | "mask" | "cancel";
  scope?: "once" | "session";
}

/** Plan 15 §7 "Overriding a finding": let one past finding through as
 * written, from the dashboard. ADMIN-ONLY. `ref` and `turn` come from the
 * finding's `prompt_filter` event; `once` needs `turn`. Refused for a
 * registered value and under a locked administrator's row (other than ask);
 * under a locked `ask` row only `once` (plan 15 §12, 2026-10-04). */
export interface LetPromptFindingThroughOpRequest extends BaseRequest {
  op: "letPromptFindingThrough";
  session: string;
  category: string;
  ref: string;
  turn?: string;
  scope: "once" | "session";
}

/** Plan 15 §7: the pending prompt holds with the human's own found text.
 * HUMAN PLANE. */
export interface PromptHoldsOpRequest extends BaseRequest {
  op: "promptHolds";
}

export interface PromptHoldWire {
  approvalId: string;
  session: string;
  category: string;
  filterId?: string;
  /** The found text (cut to 2000 characters); absent when this arbiter has
   *  not seen the message since it started. */
  span?: string;
  fallback?: "mask" | "redact";
  firstSeen: number;
  lastSeen: number;
  /** Time left before the default applies (0: it already did). */
  timeoutMs: number;
  /** A locked administrator's `ask` row covers the category (plan 15 §12,
   *  2026-10-04): answer it for this message only; a session answer is
   *  refused. */
  onceOnly?: true;
}

export interface PromptHoldsResultWire {
  holds: PromptHoldWire[];
  /** The deadline a new hold gets (ms). */
  timeoutMs: number;
}

/** Plan 15 §8.1: the prompt filters as the developer dashboard's panel shows
 * them. Data plane: names, switches, actions, the exceptions WITHOUT their
 * patterns, and pack COUNTS; never a value, a pack's regex, a keyword or an
 * exception's pattern (those are `promptFilterPacks` and `promptExceptions`,
 * human plane: plan 15 §13.7 item 4). */
export interface PromptFiltersOpRequest extends BaseRequest {
  op: "promptFilters";
}

export type PromptActionWire = FilterPromptFindingWire["action"];
export type PromptSetByWire = "default" | "you" | "administrator";

/** A prompt filter plugin as the panel shows it (plan 15 §4.3, §8.1):
 *  its pin, its model, its last run, the confinement it runs under. Never a
 *  prompt. */
export interface PromptPluginWire {
  exec: string;
  sha256: string;
  script?: string;
  scriptSha256?: string;
  /** The other files it loads, pinned (plan 15 §13.5 item 6). */
  modules?: Array<{ path: string; sha256: string }>;
  cost: "model" | "inline";
  /** `required`: the policy names a local model (`endpoint`). */
  needsEndpoint: boolean;
  deadlineMs: number;
  runs: number;
  errors: number;
  lastMs?: number;
  lastAt?: string;
  lastError?: string;
  lastErrorAt?: string;
  lastEndpoint?: string;
  /** The legs the probe found (absent until the first probe ran). */
  confinement?: { guard: boolean; landlock: boolean; seccomp: boolean; namespaces: boolean; notes: string[] };
}

export interface PromptFiltersResultWire {
  filters: Array<{
    id: string;
    kind: "built-in" | "pack" | "plugin";
    /** A classifier plugin's model (`endpoint:` in its switch, §5). */
    endpoint?: string;
    /** A plugin's pin, model and last run. */
    plugin?: PromptPluginWire;
    on: boolean;
    setBy: PromptSetByWire;
    locked: boolean;
    /** The administrator's file that set or locked it. */
    file?: string;
    onError: "block" | "pass";
    /** True when a policy wrote `on_error` (else the §4.4 default). */
    onErrorSet: boolean;
    /** False when switched on but unable to run (`problem` says why). */
    available: boolean;
    problem?: string;
    categories: Array<{ category: string; action: PromptActionWire }>;
    origins: Array<{ origin: "human" | "harness" | "side-call"; floor: string }>;
  }>;
  /** Phase 2: the category → action rows in force and the fallback. */
  actions?: Array<{ category: string; action: PromptActionWire; setBy: PromptSetByWire; locked: boolean; file?: string }>;
  fallback?: PromptActionWire;
  /** The exceptions, without their patterns (a pattern may hold the
   *  person's own words: `promptExceptions`, human plane). An arbiter before
   *  2026-10-03 also sent `match` here. */
  exceptions?: Array<{ category: string; setBy: PromptSetByWire; file?: string; inForce: boolean }>;
  signedOnly?: boolean;
  /** Each pack: where it lives and how big it is (counts only). */
  packs?: Array<{
    id: string;
    source: "user" | "admin";
    file: string;
    version: string;
    description?: string;
    signedBy: string | null;
    /** Why it does not run although loaded (unsigned under signed_only). */
    ignored?: string;
    patterns: number;
    keywordGroups: number;
    keywords: number;
    hashedKeywords: number;
    categories: string[];
    /** A plugin pack (§4.3): a file only, never edited from the panel. */
    plugin?: boolean;
  }>;
  /** Pack files refused whole, with their problems. */
  packProblems?: Array<{ file: string; source: "user" | "admin"; pack?: string; problems: string[] }>;
  /** The person's entries a locked administrator's row keeps out of force. */
  conflicts?: string[];
  /** Where the person's packs live (the panel's pack editor writes there). */
  userPackDir?: string | null;
  enforcing: boolean;
  digest: { policy: string; packs: string; values: string };
  /** How many registered values the filter matches against (no value). */
  registeredValues: number;
}

/** Plan 15 §13.7 item 4: the prompt filter's exceptions WITH their patterns
 * (`*@example.com`, or the person's own words), in the order `promptFilters`
 * lists them. HUMAN PLANE: from the data socket the agent's processes would
 * learn what the filter lets through as written. Enforcement needs none of
 * it outside the arbiter (the engine matches exceptions itself). */
export interface PromptExceptionsOpRequest extends BaseRequest {
  op: "promptExceptions";
}

export interface PromptExceptionsResultWire {
  exceptions: Array<{ category: string; match: string; setBy: PromptSetByWire; file?: string; inForce: boolean }>;
}

/** Plan 15 §8.1: every pack in full (patterns with their regex, plain
 * keywords; hashed keywords as a count). HUMAN PLANE: an organization's
 * patterns and a person's keyword list stay out of the agent's world. */
export interface PromptFilterPacksOpRequest extends BaseRequest {
  op: "promptFilterPacks";
}

export interface PromptFilterPackDetailWire {
  id: string;
  source: "user" | "admin";
  file: string;
  version: string;
  description?: string;
  signedBy: string | null;
  /** True when the panel may edit it (the person's own, unsigned). */
  editable: boolean;
  /** A plugin pack (plan 15 §4.3): its pin and settings, and the categories
   *  it may report. Never editable from the panel. */
  plugin?: { exec: string; sha256: string; script?: string; scriptSha256?: string; modules?: Array<{ path: string; sha256: string }>; args: string[]; cost: "model" | "inline"; endpoint: "required" | "none"; deadlineMs: number };
  categories?: Array<{ category: string; level?: string }>;
  patterns: Array<{ id: string; category: string; regex: string; check?: string; level?: string }>;
  keywords: Array<{ category: string; match: "word" | "substring"; hashed: boolean; count: number; words?: string[]; level?: string }>;
}

export interface PromptFilterPacksResultWire {
  packs: PromptFilterPackDetailWire[];
  packProblems: Array<{ file: string; source: "user" | "admin"; pack?: string; problems: string[] }>;
}

/** Plan 15 §8.1: typed edits to one of the person's packs (pack-edit.ts).
 * ADMIN-ONLY (the person's decision, audited). `dryRun`: validate and count
 * matches over the fixed corpus and `sample`, write nothing. */
export interface PromptPackEditOpRequest extends BaseRequest {
  op: "promptPackEdit";
  edits: unknown;
  dryRun?: boolean;
  /** Text the panel counts each pattern's matches over (the test bench's). */
  sample?: string;
  requestedBy?: string;
}

export interface PromptPackEditResultWire {
  ok: boolean;
  problems?: string[];
  pack?: string;
  file?: string;
  created?: boolean;
  changes?: Array<{ direction: "relax" | "tighten"; subject: string; detail: string }>;
  /** Each set pattern's matches: the fixed ordinary corpus and the sample. */
  counts?: Array<{ id: string; corpus: number; sample: number }>;
  dryRun: boolean;
}

/** Plan 10 §2.2 backstop: does this text contain a registered secret VALUE
 * verbatim (values shorter than the fingerprint floor are skipped)? */
export interface ScanSecretValuesOpRequest extends BaseRequest {
  op: "scanSecretValues";
  text: string;
}

/** Secret-discovery.md §2.8, "A document block": the text the model proxy
 * forwards in place of a tool result's `document` block (a PDF, base64):
 * the twin's text for a registered personal document's twin or the document
 * itself as registered at `origin`, else the PDF's text layer; null when
 * there is none (the proxy then masks the result whole). On the data
 * socket: it answers a text the caller already holds, or a twin's. */
export interface DocumentTextOpRequest extends BaseRequest {
  op: "documentText";
  /** The block's base64 data. */
  data: string;
  mediaType: string;
  /** The absolute path the tool read (Claude Code's `Read` `file_path`, in
   *  HumanView spelling). */
  origin?: string;
  sessionKey?: string;
}

export interface DocumentTextResultWire {
  text: string | null;
  /** The registered document whose twin `text` is. */
  twinOf?: string;
  reason: string;
}

/** Plan 10 §4.3: the NETWORK exit of a tainted process. The guard (direct
 * connects) and the net-proxy (proxied HTTP) ask what a process holds and
 * where it may go: the INTERSECTION of the `bindings` of every secret in its
 * taint, its own rows and its ancestors' (confidentiality plan 13 D1; the
 * union before 2026-10-02). `tainted: false` ⇒ no restriction from this
 * leg. */
export interface TaintedProcessBindingsOpRequest extends BaseRequest {
  op: "taintedProcessBindings";
  procKey: string;
  /** The opener's ancestor chain (nearest first), so a fork-only child's
   * edges are recorded before the lookup. */
  ancestors?: string[];
  session?: string;
  /** Plan 13 D2: processes whose taint reached this one NOT through its
   * parents (the writer of a pipe, FIFO or socket pair it reads; an orphan's
   * lost holders). Their taint is unioned in; no lineage edge is recorded. */
  flowsFrom?: string[];
  /** Plan 13 §5.4: the destination the caller is about to refuse (the
   * net-proxy names it once its own check found it unbound). Attested
   * channels only: the human's answer for {session, these files} × this
   * destination is consulted and spent, or a question filed naming every
   * file (`ask` in the result). Ignored from the data socket.
   * confidentiality.md §4 (2026-10-12): a process that holds only what ONE
   * HIGH session read (its `session` rows) asks that session's network
   * question instead (`session-net:<session>` × host, `question: "session"`). */
  destination?: string;
  /** Ask only the HIGH session's question, never a holder's send question
   * (the guard's direct connect, which names an address, not a host a file
   * rule could take). */
  sessionAskOnly?: boolean;
}

export interface TaintedProcessBindingsResultWire {
  tainted: boolean;
  level: string | null;
  files: string[];
  /** Host specs (`host`, `host:port`, `*.suffix`, an IP/CIDR) the process may
   * still reach. Empty with `tainted: true` ⇒ nothing beyond loopback. */
  bindings: string[];
  /** With `destination` outside `bindings` (attested): the human's answer
   * (`approved` lets this send go: a once is spent by this answer) or the
   * question filed (`pending`). Absent: no destination, bound, or a data
   * socket ask. */
  ask?: { approvalId: string; status: "pending" | "approved" | "denied"; scope?: ApprovalScope; question?: "session" | "holder" };
}

/** Plan 13 §5.4, §9 R2: the policy edit an *Always* on one file of a
 * holder's send question files (holder-send-ask.ts `holderBindEdit`): that
 * file's rule gains the destination, nothing else. A read: it describes the
 * edit, which the dashboard applies on the admin channel (`policyPropose` +
 * `resolvePolicyProposal`, the Rules page's path). Refused when the row is
 * not a waiting holder's send question, the file is not one of its files
 * that blocks, its rule cannot take the host, or the edit would loosen any
 * other rule. */
export interface HolderSourceBindingOpRequest extends BaseRequest {
  op: "holderSourceBinding";
  approvalId: string;
  /** The file (as the row's `holderSources` names it). */
  path: string;
}

export interface HolderSourceBindingResultWire {
  edits: unknown[];
  /** The rule the edit writes (normalized path). */
  rule: string;
  /** The edit's relaxations as the arbiter's preview names them: exactly
   * this rule's (`{facet: "paths", subject}`). */
  relaxes: Array<{ facet: string; subject: string }>;
  /** The items the edit was planned from, with their versions in this read
   *  (policy-surface.md §8.4.6 "An item-level version"): the file's own
   *  rule and the rule that decides its label now. The dashboard proposes
   *  the edit with them (`policyPropose.basedOn`), so a change to either in
   *  between refuses it, nothing written. Absent from an older arbiter. */
  basedOn?: PolicyItemVersionWire[];
}

/** Plan 13 D6: does ANY process of a session hold a secret (a raw read on
 * record)? The net-proxy asks for a connection it cannot attribute to a
 * process (the client gone from /proc, another user's): the sender may be a
 * holder, so such a leg is refused while the answer is yes. Absent `session`
 * ⇒ every session. Read-only; it names files, never their contents. */
export interface SessionSecretTaintOpRequest extends BaseRequest {
  op: "sessionSecretTaint";
  session?: string;
}

export interface SessionSecretTaintResultWire {
  tainted: boolean;
  /** The strictest level any process of the session holds, or null. */
  level: string | null;
  files: string[];
}

/** Plan 13 D6, a blind tunnel's chunks (2026-10-07): every process key the
 * store would answer `taintedProcessBindings` tainted for, by its own rows,
 * its recorded parents (the guard's and claimed) or its recorded flows: the
 * keys with a raw-read row, closed forward over those edges. Every session's.
 * The net-proxy narrows it to the live processes holding a tunnel's client
 * socket before each chunk (a child forked after the CONNECT that read a
 * secret is one), so it need not rescan every process's descriptors. A
 * process outside the set is tainted only through a /proc ancestor the store
 * has no edge for, which the caller adds by walking the live set's children.
 * Read-only; it names process keys, never files or contents. */
export interface SecretTaintedProcessesOpRequest extends BaseRequest {
  op: "secretTaintedProcesses";
}

export interface SecretTaintedProcessesResultWire {
  procKeys: string[];
}

/** Plan 10 §4, filesystem exit: a tainted process opened `path` for writing;
 * the file gets a derived label at the taint's level (Plan 9's store, keyed
 * by the writing process instead of a session). */
export interface LabelWrittenPathTaintedOpRequest extends BaseRequest {
  op: "labelWrittenPathTainted";
  path: string;
  procKey: string;
  ancestors?: string[];
  session?: string;
  /** Plan 13 D2: as `taintedProcessBindings`'s. */
  flowsFrom?: string[];
}

export interface LabelWrittenPathTaintedResultWire {
  labeled: boolean;
  level: string;
  reason: string;
}

/** Confidentiality plan 13 D4: the derived labels, for the guard's program
 * gate. The guard keeps the list it was given and asks again for what
 * changed after the `gen` it saw, in the `epoch` it saw (another epoch, a
 * restarted arbiter, answers every row). Only rows whose path classifies a
 * secret level now are listed (an exact human `public` label over a derived
 * row releases it); a row removed later is not reported (the guard keeps
 * gating it until its next launch). Axis OFF ⇒ none. */
/** A SESSION's machine label on one exact path (session-path-labels.ts):
 *  `no-model`, bound nowhere, in memory only, until the session's labels are
 *  cleared. Raise-only, so a data-plane op (the proxy registers OpenCode 2's
 *  background output file, supported-agents.md §2.3 item 7). */
export interface SessionPathLabelOpRequest extends BaseRequest {
  op: "sessionPathLabel";
  path: string;
  sessionKey: string;
  reason?: string;
}

export interface SessionPathLabelResultWire {
  labeled: boolean;
  /** The normalized path labelled (null when not labelled). */
  path: string | null;
  level: "no-model" | null;
  reason: string;
}

/** Drop a session's labels (the launcher at the session's end). Lowers
 *  protection, so the human plane only. */
export interface ClearSessionPathLabelsOpRequest extends BaseRequest {
  op: "clearSessionPathLabels";
  sessionKey: string;
}

export interface ClearSessionPathLabelsResultWire {
  cleared: number;
}

export interface DerivedLabelsSinceOpRequest extends BaseRequest {
  op: "derivedLabelsSince";
  epoch?: string;
  since?: number;
}

export interface DerivedLabelsSinceResultWire {
  epoch: string;
  gen: number;
  labels: Array<{ path: string; level: string }>;
}

/** 2026-10-17 (confidentiality.md §6, "Read by a program the launch did not
 * see"): where the human labels above `public` lie, for the guard's gate of a
 * labelled file the launch did not register. `key`: the answer last seen. */
export interface LabelRootsSinceOpRequest extends BaseRequest {
  op: "labelRootsSince";
  key?: string;
  /** The guard's session (2026-10-17): its launch HOME's catalog places are
   *  listed too (`sessionHome`). */
  session?: string;
}

/** The catalog's name prefilter for the guard (2026-10-17,
 *  confidentiality.md §6 "Read by a program the launch did not see"). */
export interface GuardCatalogWire {
  /** secret-catalog.ts `NameAnchor`s: a regular file whose name meets one
   *  is a candidate (the arbiter's `labelledLevel` decides). */
  names: Array<{ exact?: string; prefix?: string; suffix?: string; contains?: string; notSuffixes?: readonly string[]; ci?: boolean }>;
  /** The HOMEs the catalog is read in (the arbiter's, the launch's): a
   *  directory below the deepest one holding the file (below `/` outside
   *  every one) named in `skipDirs` above or here spares the file. */
  homes: string[];
  /** Directory names besides the walk's skipped ones below which a
   *  name-matched file is not gated (secret-discovery.ts
   *  CATALOG_GATE_SKIP_DIRS: `site-packages`, `dist-packages`). */
  skipDirs: string[];
}

export interface LabelRootsSinceResultWire {
  key: string;
  /** True when `key` named this very list: no rows are sent. */
  unchanged: boolean;
  /** A literal label's path, or a pattern's literal directory prefix (`/`
   *  when it has none) with its last segment's literal anchors (`shape`);
   *  since 2026-10-17 also each catalog prefix (secret-discovery.ts
   *  `catalogGateRoots`). */
  roots: Array<{ path: string; shape?: { head: string; tail: string; exact: boolean } }>;
  /** The directory names the discovery walk never enters (secret-discovery.ts
   *  SKIP_DIRS: `.git`, `node_modules`, `target`, …): a file below a root
   *  inside one of them is not gated, as the walk would not have registered
   *  it (the toolchains in a labelled project keep working). */
  skipDirs: string[];
  /** The catalog's name prefilter (absent with the axis OFF, and in an
   *  unchanged answer, which keeps the one in force). */
  catalog?: GuardCatalogWire;
}

/** The level `path` classifies at now (labels, then the catalog; the
 *  session's launch HOME as `decideSecretOpen` reads it). */
export interface LabelledLevelOpRequest extends BaseRequest {
  op: "labelledLevel";
  path: string;
  session?: string;
  /** 2026-10-17 (confidentiality.md §6, "The base follows the shell"): the
   *  AGENT process itself opened `path` for reading (the guard saw the open
   *  in the kernel). On the human plane, a file above `public` is recorded
   *  (`ProvenanceStore.recordAgentOpen`) for the classify of the file tool
   *  that named it by a relative path; from the data socket nothing is. */
  agentOpen?: boolean;
}

export interface LabelledLevelResultWire {
  level: string;
  key: string;
  /** With `agentOpen`: the open was recorded. */
  recorded?: boolean;
}

/** Confidentiality plan 13 D4: the derived label of `from` follows its file
 * to `to` (a rename, a hard link, or the same file met under another name at
 * an open). Raise-only: `to` takes `from`'s derived level; a `from` with no
 * derived row moves nothing. Axis OFF ⇒ nothing. */
export interface FollowDerivedLabelOpRequest extends BaseRequest {
  op: "followDerivedLabel";
  from: string;
  to: string;
  how: "rename" | "link" | "identity";
  session?: string;
}

export interface FollowDerivedLabelResultWire {
  labeled: boolean;
  level: string | null;
  reason: string;
}

export interface ScanSecretValuesResultWire {
  /** The symbols whose value appears in the text: the whole value, or (a
   *  multi-line secret) one of its long lines (`how`). */
  hits: Array<{ symbol: string; level: string; how?: "value" | "line" }>;
}

/** Plan 10 §4.1: the interposer's question at an open of a registered
 * secret. The arbiter decides from the law (readers, pins, the consumer
 * table, the ask mode) and, on `raw`, records the process taint BEFORE it
 * answers, so the guard injects the descriptor knowing the record exists. */
export interface DecideSecretOpenOpRequest extends BaseRequest {
  op: "decideSecretOpen";
  /** The registered secret's real path. */
  path: string;
  /** `/proc/<pid>/exe` of the opener. */
  exe: string;
  sha256?: string;
  isAgent: boolean;
  procKey: string;
  /** The opener's parent (a fork-only child's lineage edge, §4.2). */
  /** The opener's ancestor executables, nearest first (the guard walks
   *  /proc): a reader with `from:` counts only under that app. */
  ancestorExes?: string[];
  /** Plan 13 D8: per `ancestorExes` entry, same order: that ancestor is out
   *  of the agent's reach and runs with a clean loader environment. A
   *  `from:` reader counts only under a trusted ancestor. Absent = none is. */
  ancestorTrusted?: boolean[];
  /** Plan 13 D8: the opener's executable (the inode it runs) and every
   *  directory above it are unwritable by the agent's uid. Only such a binary
   *  is pinned on first use. Absent = not. */
  exeSystem?: boolean;
  /** Plan 13 D8: the loader / interpreter variables the opener runs with
   *  set to a value the launch did not give, by name, and `code:<path>` for
   *  an executable file mapped into it that the agent can write;
   *  `args:<program> <what>` for code its command line hands it; and
   *  `runs:<family>` for a binary whose content is a language interpreter's
   *  under a name the code-running list does not know (Plan 13 §8 decision
   *  (b) by content, 2026-10-03); and `pkg:<package>` for one whose content
   *  is a program of a package of printers or launchers (GNU coreutils,
   *  findutils, util-linux, …) under a name neither list knows, judged a
   *  printer (Plan 13 D8 (13), P0 item 14). `[]` = clean; absent
   *  = not checked, and the opener is then no reader. */
  openerEnv?: string[];
  /** Plan 13 R5: for an interpreter (python, node, a shell, perl), the
   *  script it runs as the guard read it: absolute canonical path, sha256,
   *  out of the agent's reach (`system`), isolated from per-user code, and
   *  whether another process traces it. A `script:` reader entry matches
   *  only on these (`scriptFactsProblem`). Absent for any other program. */
  script?: { path: string; sha256?: string; system: boolean; isolated: boolean; traced: boolean };
  /** Plan 13 R5: an interpreter that runs no script an entry could pin
   *  (inline code, a module, stdin, a relative path, …): why. */
  scriptProblem?: string;
  parentKey?: string;
  /** Plan 13 D7: the opener's live ancestor proc keys, nearest first (the
   *  guard's `/proc` walk at the open, stopped below the guard). Recorded as
   *  lineage edges, first edge winning, so a reader under a subshell that
   *  never exec'd is in its call's tree. Absent: the `parentKey` edge alone. */
  ancestorKeys?: string[];
  /** Plan 13 D7, the orphan subshell: the guard found no agent process among
   *  the actor's live ancestors and names the ORPHAN ROOT above it (the
   *  topmost ancestor, re-parented to a reaper, born after the agent): a tree
   *  whose real parent, a tool call's shell, exited before it acted. Folded
   *  into every call relayed no later than it was first seen. Only widens a
   *  fold, so it is kept from either socket. */
  orphanRoot?: string;
  session?: string;
  /** known | always | never (§11.1). */
  ask?: string;
  /** §12.2: the guard's LAST ask of a held open, its ceiling passed. A row
   * still pending is recorded as a denial (`held for N s, …`, the "held:"
   * note of §11.8) and answered `deny`; the row itself stays pending, so an
   * answer given later applies to the next attempt with no new prompt. */
  heldMs?: number;
}

/** sandbox-security-review-2026-09-28 finding 6: the guard's question when a
 * program in the agent's tree changes a file under an `ask` write-protect
 * entry (a shell startup file, a systemd user unit, a git hook). Answered from
 * a prior human verdict for (program, file), else a pending Inbox row and
 * `ask` (the guard holds the call and asks again). `heldMs` = the hold's
 * ceiling passed: `deny`, the row stays pending.
 *
 * The verdict names the writer's BINARY (write-protection.md §2.1, the Plan 13
 * D8 follow-up): keyed `write:<exe>#<sha256>`. The guard reports the same
 * identity facts as for a secret open (`DecideSecretOpenOpRequest`); a writer
 * whose `openerEnv` is absent or not empty is refused without a row. */
export interface DecideProtectedWriteOpRequest extends BaseRequest {
  op: "decideProtectedWrite";
  /** The path being changed. */
  path: string;
  /** `/proc/<pid>/exe` of the writer. */
  exe: string;
  /** sha256 of the inode the writer runs, hex; absent when the guard could
   *  not read it (the verdict is then keyed by the path alone). */
  sha256?: string;
  /** The writer's executable and every directory above it are out of the
   *  agent's reach. Shown to the human (the Inbox says when the agent could
   *  have written the program); it does not decide. */
  exeSystem?: boolean;
  /** As `DecideSecretOpenOpRequest.openerEnv`, for the writer: the loader /
   *  interpreter variables set to a value the launch did not give, and
   *  `code:<path>` for agent-writable code mapped in. `[]` = clean; absent =
   *  not checked, which refuses the write. */
  openerEnv?: string[];
  procKey: string;
  /** Plan 13 §8 decision (c): for a writer that is a script interpreter, the
   *  script it runs as the guard read it (as `DecideSecretOpenOpRequest`'s):
   *  the verdict then names the script too. Absent for any other program. */
  script?: { path: string; sha256?: string; system: boolean; isolated: boolean; traced: boolean };
  /** Plan 13 §8 decision (c): an interpreter writer running no script a pin
   *  could name (inline code, stdin, …): why. Its verdict names its run. */
  scriptProblem?: string;
  /** The entry's label; only the launcher's own labels are shown. */
  label?: string;
  session?: string;
  heldMs?: number;
}

export interface DecideProtectedWriteResultWire {
  verdict: "allow" | "deny" | "ask";
  reason: string;
  /** `ask`: the Inbox row the human resolves. */
  approvalId?: string;
}

export interface DecideSecretOpenResultWire {
  verdict: "raw" | "twin" | "deny" | "ask";
  app: string;
  level: string;
  reason: string;
  pinNeeded: boolean;
  /** `ask`: the Inbox row the human resolves (§11.1). The guard re-asks
   * until the verdict changes or its ceiling passes. */
  approvalId?: string;
}

export interface CallTaintResultWire {
  level: string | null;
  files: string[];
  apps: string[];
  /** secret | clear | mask; `secret` whenever any taint exists and no app rule says otherwise. */
  rule: "secret" | "clear" | "mask";
  mask: string[];
  root: string | null;
  /** Opens refused within the tree (plan 10 §11.8). */
  denied: Array<{ path: string; app: string; reason: string }>;
  /** Plan 10 §11.8, "Refused connections": connections the egress proxy
   *  refused from a process of the tree, by kind (never a host). Absent
   *  when none. Explains only: never lowers a mask. An entry with
   *  `unattributed: true` (and `app: ""`) is a refusal the proxy tied to no
   *  process, made while the call ran ("A refusal no process is tied to"). */
  refusedEgress?: Array<{ app: string; kind: EgressRefusalKind; unattributed?: true }>;
  /** Plan 10 §11.8, "Blocked commands": commands of the tree the exec-wrap
   *  shim refused, by program name and the approval kind that refused them
   *  (arbiter policy/blocked-exec.ts, recomputed from the guard's argv
   *  record; never an argument), or `codex_sandbox` for a run under Codex's
   *  own sandbox with its network off, which refused the shim's connection
   *  (2026-10-09). For a call the recorder did not bind, also the shim runs
   *  under the processes that exec'd the call's recorded command. Absent
   *  when none. Explains only: never lowers a mask. */
  blockedExec?: Array<{ app: string; kind: BlockedExecKind }>;
  /** Plan 10 §11.8: the `output` is (part of) this registered file's
   * structured twin, exactly its whole-file twin (`twinWhole`), or a
   * key listing of it (`twinKeys`), in a tree
   * the guard recorded with no raw secret open; with `dirListing`, the
   * folders (then the files) a names-only `ls` listed. Absent otherwise. */
  twinOf?: string[];
  /** Plan 10 §11.8, "A document's own twin" (2026-10-12): with `twinOf`,
   * the output is exactly the file's WHOLE-FILE twin (its base symbol and
   * the file's own terminator, after Codex's head), not a piece of a
   * structured twin; the proxies word the `twin:` line for it. */
  twinWhole?: true;
  /** Plan 10 §11.8, "A key listing" (2026-10-16): with `twinOf`, the
   * output holds no token and is a key listing of the file's
   * structured twin (its keys in order, `cut -d= -f1 .env`); the proxies
   * word the `twin:` line for it. */
  twinKeys?: true;
  /** Plan 10 §11.13, "A config with no secret" (2026-10-17): with `twinOf`,
   * the output holds no token and is a piece of the file's OWN-TEXT twin
   * (an exhaustive shape whose extraction found no secret value, a file the
   * command names); the proxies word the `twin:` line for it. */
  twinOwn?: true;
  /** Plan 10 §11.8, "A folder's names" (2026-10-17): with `twinOf` (the
   * paths `ls` listed), the output is exactly what one plain `ls` (no `-l`,
   * no chain or pipe) prints for those folders now, names only
   * (policy/dir-listing.ts); the proxies add a `listing:` line. */
  dirListing?: true;
  /** With the confidentiality axis on: `tree` = the fields describe the
   * call's process tree; `session` = the tree is not known (plan 13 D7: the
   * call-root recorder did not bind the call, and for an `unmappedTool`,
   * plan 10 §11.12, no tree was found) and the session holds a raw read, so
   * the fields are every raw secret read of the session (rule `secret`: the
   * whole output is masked at `level`); `unmapped` = an `unmappedTool`
   * Mandu has no mapping for (plan 10 §11.18): masked whole at `no-model`
   * whatever the session read. */
  evidence?: "tree" | "session" | "unmapped";
  /** With `evidence: "unmapped"` (plan 10 §11.18): the product copy saying
   *  why the whole result is hidden and how to let it through. */
  why?: string;
}

/** `isProcessTainted` ⇒ taint status + origin host if tainted. */
export interface IsProcessTaintedResult {
  tainted: boolean;
  originHost?: string;
}

/** `fileTrust` ⇒ untrusted flag + origin string if untrusted. */
export interface FileTrustResult {
  untrusted: boolean;
  origin?: string;
}

/** Pre-symbolize a secret file so the agent learns its NAME, never its bytes
 * (confidentiality.md §7.2; plan 4′). The ARBITER reads the file — it runs
 * outside the agent's sandbox — so secret bytes never enter the caller's
 * process or this request. REFUSED while the confidentiality axis is OFF. */
export interface RegisterSecretOpRequest extends BaseRequest {
  op: "registerSecret";
  /** Absolute path of the secret file. */
  path: string;
  sessionKey?: string;
  /** The LAUNCH's HOME, for the catalog's `~/…` prefix rules. The arbiter is
   *  a resident daemon whose own HOME may differ from the session's (a
   *  fixture home, a test, a launch with HOME overridden): without this,
   *  `~/.ssh/id_x` under the session's HOME matched nothing and was left raw
   *  (fixture-home table, 2026-09-24). Absent ⇒ the arbiter's homedir(). */
  home?: string;
  /** The launch's values of the variables that move an agent's login file
   *  (discoverSecrets' `loginEnv`): another agent's login a variable moved
   *  out of the catalog's places is registered `no-model`, as the walk found
   *  it (secret-discovery.md §1.10). Known names, absolute paths only. */
  loginEnv?: Record<string, string>;
}

/** List every registered secret ({path, symbol}) — the launcher builds the
 * twin set from this; the dashboard renders the standing surface. */
export interface SecretRegistryOpRequest extends BaseRequest {
  op: "secretRegistry";
}

/** Discover which catalog secret files exist under `roots` (HOME + workspace).
 * Filesystem discovery, plus (2026-10-19) the catalog's content tier: the
 * arbiter reads small JSON, YAML and TOML config files and records a found
 * label on each it reads a credential in (secret-discovery.md §2.6). The
 * answer carries paths and field names, never a value. */
export interface DiscoverSecretsOpRequest extends BaseRequest {
  op: "discoverSecrets";
  roots: string[];
  /** The launch's HOME (see RegisterSecretOpRequest.home). */
  home?: string;
  /** fs-sync's view state base for this launch (the Mandu home's `state/`;
   *  default `<home>/.mandu/state`): pruned from the walk, and the view map it
   *  persists names the AgentView worktrees to walk instead
   *  (secret-discovery.md §1.9). */
  stateBase?: string;
  /** The LAUNCH's values of the variables that move a package cache
   *  (`CARGO_HOME`, `GOMODCACHE`, …; secret-discovery.ts PACKAGE_CACHE_ENV,
   *  secret-discovery.md §1.9 G): those names only, never the rest of the
   *  environment. Unknown names and non-string values are dropped. */
  cacheEnv?: Record<string, string>;
  /** The launched agent (the launcher's `--target`), so the walk leaves
   *  only ITS login files raw and discovers every other agent's
   *  (secret-discovery.ts `keptLoginOwners`, secret-discovery.md §1.10).
   *  Absent (an older launcher, a dry run naming no agent): every agent's
   *  login stays raw, as before. */
  target?: string;
  /** The CLI the AI helper runs in the agent's world (`claude` or
   *  `codex`); absent when it runs none. Its login stays raw too. */
  ullmBinary?: string;
  /** The LAUNCH's values of the variables that move an agent's login file
   *  (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_DATA_HOME`;
   *  secret-discovery.ts LOGIN_ENV): those names only, absolute paths only. */
  loginEnv?: Record<string, string>;
}

/** The `discoverSecrets` reply (secret-discovery.md §1.3): the files
 *  to mask plus the "not covered" ledger. `files` is the pre-2026-09-24 shape;
 *  the rest is what `mandu doctor --secrets` and the launch notice render.
 *  `agentLogin` names the agent whose login file it is, for one this launch
 *  does not run on (secret-discovery.md §1.10). */
export interface DiscoverSecretsResultWire {
  files: Array<{ path: string; level: string; rule: string; agentLogin?: string }>;
  /** Candidates the walk left out, with the reason (capped list). */
  skipped: Array<{ path: string; reason: string }>;
  /** Complete per-reason counts (never capped). */
  counts: Record<string, number>;
  limits: { maxDepth: number; maxFiles: number };
  /** A cap stopped the walk: files beyond it were never examined. */
  truncated: boolean;
  /** The `depth` records grouped by folder (two levels below their walk
   *  root), the most first, at most 20 (secret-discovery.md §1.9 H).
   *  Absent from an arbiter older than 2026-10-11. */
  depthAreas?: Array<{ path: string; count: number }>;
  /** The catalog's content tier (secret-discovery.md §2.6, 2026-10-19): the
   *  config files this walk read a credential in (each also in `files`,
   *  rule `content:secret-key`) with the deciding field (never a value);
   *  the found labels' files it read and found none in (their labels are
   *  dropped); how many candidates it read, and how many its caps left
   *  unread. Absent from an older arbiter. A personal document (§2.7, rule
   *  `content:personal-document`) is in `found` too, with `kind:
   *  "document"` and its kind as the field (`bank-statement`); `documents`
   *  counts the documents read and left unread by their own caps. */
  found?: Array<{ path: string; field: string; kind?: "document" }>;
  cleared?: string[];
  content?: { read: number; capped: number };
  documents?: { read: number; capped: number };
}

/** Scan the reachable git history of the repository holding each root for
 *  secret-shaped blobs (docs/design/confidentiality/secret-discovery.md §3; the C17 boundary).
 *  DATA plane, read-only: the arbiter reads the blobs (it is the one
 *  component that may hold secret bytes) and answers with findings that
 *  carry no value, only a kind, a line and a fixed mask. Asynchronous: a
 *  socket call runs it; one scan at a time (a second is refused while one
 *  runs). With the confidentiality axis OFF the answer is empty. */
export interface ScanSecretHistoryOpRequest extends BaseRequest {
  op: "scanSecretHistory";
  /** Absolute directories; the work tree holding each is scanned (at most
   *  HISTORY_ROOTS_MAX). */
  roots: string[];
  /** The launching user's HOME, for `~/` labels and catalog rules. */
  home?: string;
}

/** The `scanSecretHistory` reply: the scan, and whether the axis is on (OFF:
 *  nothing was scanned). */
export type ScanSecretHistoryResultWire = SecretHistoryScan & { axis: boolean };

// ── policy suggestions (confidentiality-plan-14-policy-suggestions.md §4, §5) ──
// Mandu's scan turns its findings into typed edits (lock-path / lock-blob at
// no-model) and files each as a SUGGESTION: a row of policy_proposals with
// kind "suggestion", requestedBy "mandu:scan" (only the arbiter sets it), and
// a finding key. Nothing applies until a human does: `applySuggestion` (data
// plane, a pure tightening only) or `resolvePolicyProposal` (admin). "Not a
// secret" (`dismissSuggestion`) withholds protection, so it is ADMIN-ONLY. No
// field of any of these carries a secret value: the evidence is the scan's
// fixed masks, and the sentence is built from the edits.

/** One suggestion as the review shows it (terminal, dashboard). */
export interface SuggestionView {
  /** The proposal id (`pp-NNNNNN`). */
  id: string;
  kind: "suggestion";
  status: "pending" | "approved" | "denied" | "superseded";
  /** Always "mandu:scan". */
  requestedBy: string;
  /** The dedup key: a pending or dismissed key is never filed twice. */
  findingKey: string;
  /** "git-history" (S1), "workspace" (S2, plan 14 §13) or
   *  "sensitivity-label" (S4, plan 14 §14.1). A workspace suggestion has one
   *  path, no commits (`blob: ""`, both commits null) and `rotate: false`;
   *  a sensitivity-label one has one path, no finding entry
   *  (`evidence.findings` is empty) and `evidence.label` (the label's ids
   *  and the MAPPING's name and level); renderers branch on this. An older
   *  reader shows either without failing (the same shape). */
  source: Suggestion["source"];
  /** The work tree (history; a workspace finding's nearest `.git` folder),
   *  else the workspace scan root. The per-folder cap groups by it. */
  repoRoot: string;
  edits: SuggestionEdit[];
  /** The rule in plain words, built from the edits. */
  sentence: string;
  evidence: Suggestion["evidence"];
  impact: Suggestion["impact"];
  historyOnly: boolean;
  /** The key was exposed: rotate it. */
  rotate: boolean;
  /** Plan 14 §14.1: only a person applies it, in the dashboard (the admin
   *  channel): a sensitivity-label lock or a contents-model answer
   *  (§14.11) below no-model. `applySuggestion`
   *  on the data socket refuses it (`relaxes`). */
  humanOnly: boolean;
  /** `source: "model-names"` only (plan 14 §14.4): the destination model's
   *  name and its answer as enums (level, reason) with the arbiter's words
   *  for the reason, the candidate's kind and file count, and the pending
   *  scan suggestions a folder rule groups. */
  model?: Suggestion["model"];
  /** Every edit is in this build's grammar (false: an op a newer arbiter
   *  filed; applying is refused as `unsupported`). */
  applicable: boolean;
  createdAt: number;
  resolvedAt: number | null;
  resolvedBy: string | null;
  /** approved: the change it became. */
  changeId: string | null;
  supersededBy: string | null;
}

/** Scan `roots` (the repositories holding them: the git-history scan; the
 *  files under them: the workspace scan, plan 14 §13) and file what the law
 *  does not cover as suggestions. DATA plane: it only files tightenings, at
 *  most SUGGESTION_CAP_PER_REPO pending per repository (both sources), and a
 *  pending or dismissed finding (or file) is never filed again. The
 *  workspace scan never opens a file the law already protects, and its
 *  answer carries paths and fixed masks only. Asynchronous and one scan at a
 *  time (shared with `scanSecretHistory`; one job runs both sources).
 *  Axis OFF: empty. */
export interface SuggestPolicyOpRequest extends BaseRequest {
  op: "suggestPolicy";
  /** Absolute paths, at most HISTORY_ROOTS_MAX. A root equal to `home` or
   *  above it is walked as a home (name hints, depth 4). */
  roots: string[];
  home?: string;
  /** Which scans run: "git-history", "workspace" and/or "sensitivity-label"
   *  (plan 14 §14.1: the Office files' labels, read in the workspace walk),
   *  each at most once. Absent: all three (so an older caller gets them).
   *  Empty or unknown: refused. */
  sources?: Array<"git-history" | "workspace" | "sensitivity-label">;
  /** Plan 14 §14.1: an EXPLICIT scan (`mandu policy suggest`, the
   *  dashboard's Scan) sets this so the Office files' labels are read and
   *  counted even while no `sensitivity_labels:` mapping is in force (the
   *  summary's `labels.unmapped` lets the person map them). Without it, and
   *  without a mapping, no Office file is opened. The launch never sets it.
   *  Ignored when "sensitivity-label" is not among the sources. */
  countLabels?: boolean;
  /** Also walk `home` as a home-tier root (§13.1). Needs `home`. */
  includeHome?: boolean;
  /** Answer after at most this many ms (the launch's budget, plan 14 §5.5):
   *  a scan still running then finishes in the arbiter and files what it
   *  finds in the background (`running: true`). Unset: wait for the scan. */
  waitMs?: number;
  /** Plan 14 §5.5 (the launch): when a scan of every source already
   *  finished over each root (or a folder holding it) in this arbiter's run,
   *  answer at once (`waitMs` 0) from the pending suggestions it left, with
   *  `lastScanAt` set, and run this scan in the background. No such scan:
   *  `waitMs` as given. An older arbiter ignores it and waits. */
  answerFromEarlier?: boolean;
}

export interface SuggestPolicyCounts {
  /** Findings the scans reported (history and workspace). */
  findings: number;
  /** Suggestions the generator built (before dedup and the cap). */
  suggested: number;
  filed: number;
  /** Already pending under the same finding key, or every subject it
   *  locks is locked by a pending suggestion of either source. */
  alreadyPending: number;
  /** Dismissed before ("Not a secret", the key or every subject it locks):
   *  never filed again. */
  dismissed: number;
  /** Over the per-repository cap: counted, not filed. */
  overCap: number;
  /** Secrets the law already covers. */
  covered: number;
  /** Thrown out by the tightening check (invalid, or relaxing). */
  dropped: number;
  /** Pending suggestions closed because the law now covers them. */
  superseded: number;
}

export interface SuggestPolicyResult {
  axis: boolean;
  /** The time budget ended first: the scan goes on in the arbiter. */
  running: boolean;
  /** Pending suggestions: the scanned repositories' when the scan ended;
   *  every pending one while it runs. */
  suggestions: SuggestionView[];
  /** Ids this scan filed. */
  filed: string[];
  covered: CoveredSecret[];
  counts: SuggestPolicyCounts;
  /** What the history scan read and what a cap left unread; null while
   *  running, with the axis OFF, or when "git-history" was not asked for. */
  scan: Pick<SecretHistoryScan, "repos" | "counts" | "capped" | "limits" | "ms"> | null;
  /** The workspace scan (plan 14 §13.3) without its findings: its roots and
   *  tiers, counts, caps (with one plain line each), limits and time; null
   *  while running, with the axis OFF, or when "workspace" was not asked
   *  for. An older arbiter omits it. */
  workspaceScan: SecretWorkspaceScanSummary | null;
  /** Plan 14 §5.5: when (epoch ms) a scan of every source last finished
   *  over all the roots in this arbiter's run: this scan's own time when it
   *  finished, else the earlier one's; null when none did. With `running:
   *  true` and a time, `suggestions` are what that earlier scan left. An
   *  older arbiter omits it. */
  lastScanAt?: number | null;
}

/** The suggestions, newest first (closes as `superseded` any pending one the
 *  law now covers). Data plane (a read). */
export interface PolicySuggestionsOpRequest extends BaseRequest {
  op: "policySuggestions";
  status?: "pending" | "approved" | "denied" | "superseded";
}

export interface PolicySuggestionsResult {
  suggestions: SuggestionView[];
}

/** Apply one pending suggestion. DATA plane: re-evaluated against the law in
 *  force and applied only when it is still a pure tightening (`via:
 *  "agent-tighten"`: the data plane is the agent's channel; `via: "tighten"`
 *  on the admin channel; recorded and undoable in History); the suggestion closes
 *  `approved` with the change id. Anything else is refused and it stays
 *  pending (a relaxation needs the admin channel's resolvePolicyProposal). */
export interface ApplySuggestionOpRequest extends BaseRequest {
  op: "applySuggestion";
  suggestionId: string;
  /** Admin channel only: who applied it (the data plane is "data-plane"). */
  requestedBy?: string;
}

export type ApplySuggestionResult =
  | { applied: true; changeId: string; delta: PolicyDeltaChangeWire[]; suggestion: SuggestionView }
  | {
      applied: false;
      /** covered: the law already says this (the suggestion is closed
       *  `superseded`); relaxes: the law moved and it would now relax;
       *  invalid: it no longer applies; stale: policy.yaml changed on disk
       *  (retry); unsupported: an edit whose op this build does not know. */
      refused: "covered" | "relaxes" | "invalid" | "stale" | "unsupported";
      problems: string[];
      suggestion: SuggestionView;
    };

/** "Not a secret": ADMIN-ONLY (it withholds protection). The suggestion is
 *  denied and its finding key dismissed, so no later scan files it again. */
export interface DismissSuggestionOpRequest extends BaseRequest {
  op: "dismissSuggestion";
  suggestionId: string;
  requestedBy?: string;
}

export interface DismissSuggestionResult {
  suggestion: SuggestionView;
}

// ── the names-only model (confidentiality-plan-14 §14.2-§14.5, step 4b) ──────
// Two data-plane ops, consent bound to the bytes: the preview builds, gates
// and KEEPS the request texts (15 minutes, in memory, under their digest);
// the send sends exactly those once, through the classifier process, and
// files what comes back as `source: "model-names"` suggestions. Names only:
// no byte of a file's content is in any request (policy-model.ts
// `NamesOnlyItem`). T2 (`tier: "contents"`, step 4c, plan 14 §14.11): the
// first 16 KiB of documents the law calls public, only to a declared
// `local: true` entry (`resolveLocalEndpoint`), filed as `model-contents`.

/** Where a model request goes, in words. */
export type ModelDestinationWire = ModelDestination;

/** Build and keep a names-only payload for a model run. DATA plane: what it
 *  may send is names the agent's own model already sees, gated. Refused when
 *  the arbiter has no classifier ("not available in this install"), for
 *  `tier: "contents"` (not built), for an undeclared `endpoint`, and while a
 *  scan runs. */
export interface ModelSuggestPreviewOpRequest extends BaseRequest {
  op: "modelSuggestPreview";
  tier: "names" | "contents";
  /** A declared policy.yaml `models:` entry; absent = the helper's default
   *  model (inspect-mcp `selectUllmConfig`). */
  endpoint?: string;
  roots: string[];
  home?: string;
  includeHome?: boolean;
}

export interface ModelSuggestPreviewResult {
  axis: boolean;
  tier: "names" | "contents";
  /** The consent's key: `modelSuggest {digest}` sends exactly these bytes.
   *  "" when there is nothing to send (nothing is kept). */
  digest: string;
  destination: ModelDestinationWire;
  /** Which local folder each `root <n>` is (shown here, never sent). */
  roots: Array<{ index: number; root: string; files: number }>;
  /** Names to be sent, requests, and the bytes of every request text. */
  items: number;
  bytes: number;
  requests: number;
  /** T1: every line to be sent, exactly as the request carries it. T2: []. */
  names: string[];
  /** T2: the documents whose head is sent: the root's number, the name
   *  relative to it (shown, never sent), the bytes sent, and whether the file
   *  is longer than its 16 KiB head. Never a byte of the text. T1: []. */
  files: Array<{ root: number; name: string; bytes: number; truncated: boolean }>;
  /** Not sent, by why (covered by the law, under a labelled folder, too
   *  long, holding the home path or the user name, over the run's cap, a
   *  detector hit or a registered value in what would be sent; T2 also: a
   *  detector flagged the file in the walk, the file was not read whole). */
  left: { covered: number; labelled: number; tooLong: number; personal: number; overCap: number; detector: number; registered: number; flagged: number; unread: number };
  promptVersion: string;
  /** The classifier's network confine: live, or why not. */
  confine: { live: boolean; note?: string };
  /** When the kept payload is forgotten (ms since epoch); 0 with no digest. */
  expiresAt: number;
  /** The walk: files examined, files the law covers (not opened), caps. */
  walk: { examined: number; covered: number; capped: string[] };
}

/** Send a kept payload (the preview's digest) and file what the model
 *  suggests. DATA plane; once per digest (a second call polls). A digest
 *  no longer held is refused ("look again"). With `waitMs` the answer comes
 *  at the latest then (`running: true`), and the run goes on. */
export interface ModelSuggestOpRequest extends BaseRequest {
  op: "modelSuggest";
  digest: string;
  waitMs?: number;
}

export interface ModelSuggestResult {
  axis: boolean;
  running: boolean;
  digest: string;
  destination: ModelDestinationWire | null;
  /** What was sent: requests answered or failed, names, bytes (the
   *  preview's). */
  sent: { requests: number; items: number; bytes: number };
  counts: {
    /** Rules that passed the closed-answer check. */
    rules: number;
    /** Suggestions built from them. */
    kept: number;
    /** Rules or answer parts thrown out (malformed, unknown id, not a
     *  tightening). */
    dropped: number;
    /** Rules folded into another (the same candidate, or under a folder rule). */
    merged: number;
    tooBroad: number;
    /** The law already says it. */
    covered: number;
    filed: number;
    alreadyPending: number;
    dismissed: number;
    overCap: number;
    failedRequests: number;
    /** T2: documents the model answered `public` (nothing filed). */
    public: number;
  };
  filed: string[];
  /** The pending model suggestions of this run. */
  suggestions: SuggestionView[];
  /** Why the run failed or stopped, in the arbiter's words; null otherwise. */
  error: string | null;
  ms: number;
}

export interface RegisterSecretResultWire {
  symbol: string | null;
  reason: string;
  /** The structured twin text (plan 10 §2.4); absent = whole-file twin. */
  twin?: string;
  shape?: string;
  fields?: number;
  /** Plan 10 §12.5: the file's reader list (named programs, pinned subset). */
  readers?: { named: number; pinned: number };
}

/** Mask the secret-shaped variables of the agent's environment (plan 10
 * §11.4): each value that is a secret is registered (`$MDU:nomodel_Env[h].NAME`)
 * and the caller puts the returned `twin` into the agent's environment. The
 * values cross the owner-only socket once, from the launcher, which holds
 * them anyway. REFUSED while the confidentiality axis is OFF. */
export interface RegisterEnvSecretsOpRequest extends BaseRequest {
  op: "registerEnvSecrets";
  /** `agentKey`: the agent's own key variable (ANTHROPIC_API_KEY), exempt by
   *  name, masked anyway when an auth grant for it is held (agent-sign-in.md
   *  §3.8); ignored without one. */
  vars: Array<{ name: string; value: string; agentKey?: boolean }>;
  sessionKey?: string;
}

export interface RegisterEnvSecretsResultWire {
  vars: Array<{ name: string; symbol: string | null; twin?: string; reason: string }>;
}

/** Which of these variable NAMES a launch would mask (plan 10 §11.4), values
 * unseen: the dry run's env inventory (`mandu doctor --secrets`). Pure over
 * the shape list and the law's `env:` section; mints nothing; answers with
 * the axis OFF too (it is a question about the law, not a registration). */
export interface EnvSecretNamesOpRequest extends BaseRequest {
  op: "envSecretNames";
  names: string[];
}

export interface EnvSecretNamesResultWire {
  /** The names that would be masked, in the order given. */
  matched: string[];
}

export interface SecretRegistryResultWire {
  entries: Array<{ path: string; symbol: string }>;
}

export interface DiscoverSecretsResultWire {
  files: Array<{ path: string; level: string; rule: string; agentLogin?: string }>;
}

/** The confidentiality axis's state for the dashboard (plan 5): the switch +
 * the STANDING RELEASE SURFACE (§6 — every registered secret and every binding
 * must be visible, because each is a standing rule). NEVER returns values. */
export interface ConfidentialityStateOpRequest extends BaseRequest {
  op: "confidentialityState";
}

export interface ConfidentialityStateResultWire {
  /** Is the axis enabled on this arbiter (confidentiality.md §11)? */
  enabled: boolean;
  /** Registered secrets: path, symbol, level, bindings — never contents.
   * Plan 10: `fields` = how many values got their own symbol (0 = whole-file
   * twin); `readers` = the programs that may open the raw file (absent = NO
   * list: the structured twin for everyone; present, even empty = a list
   * exists, and a program not on it gets `others`: `deny` (the default, §3.3)
   * or `twin`). */
  secrets: Array<{ path: string; symbol: string; level: string; bindings: string[]; fields?: number; readers?: string[];
    /** Plan 13 D8 (2026-10-03): per `readers` entry, same order, true when
     *  it admits nothing as this arbiter judges it (`entryAdmitsNothing`: a
     *  printer or a program that runs code by name, path or pinned hash, no
     *  script pin). Present with `readers`; absent from an older arbiter. */
    readersAdmitNothing?: boolean[];
    /** Plan 13 D8 (12): per `readers` entry, true when its program reads
     *  the twin (neither vetted nor vouched for: `entryReadsTwin`). */
    readersReadTwin?: boolean[];
    others?: "deny" | "twin" }>;
  /** USER LABELS (Plan 6) — part of the standing release surface, not a
   * separate concern: a `any-model` label is a standing grant of model
   * readability, and a `public` label on a catalog-matching path is a standing
   * DECLASSIFICATION. §6 requires both be visible. */
  labels: PathLabelWire[];
  /** DERIVED LABELS (Plan 9) — the files a HIGH session wrote, labeled on disk at
   * its watermark (§4/§8). A separate list from `labels` on purpose: those are
   * human decisions, these are machine taint records. Conflating them in the UI
   * would put words in the human's mouth, and §6's surface is exactly the record
   * of what the human decided. */
  derived: DerivedLabelWire[];
  /** Plan 10 §11.9: the programs that read a secret RAW as listed readers
   * (process key, program, file, level, when), newest first. The one place
   * taint can accumulate across a session is a long-lived reader; this keeps
   * it on screen. Absent on an arbiter predating plan 10. */
  taintedProcesses?: Array<{ procKey: string; app: string; path: string; level: string; session: string | null; since: number }>;
}

/** One user labeling act, on the wire. */
export interface PathLabelWire {
  path: string;
  /** "public" | "any-model" | "local-model" | "no-model". */
  level: string;
  bindings: string[];
  /** Does the label cover descendants? */
  recursive: boolean;
  /** `path` is a gitignore-style pattern (policy.yaml `paths:` only). */
  glob?: boolean;
  /** "user" | "import" (Purview/MIP ingestion is Phase C). */
  source: string;
  updatedAt: number;
  /** True when this label is WEAKER than the catalog's verdict for the path —
   * i.e. the human declassified a file the catalog calls a credential. */
  declassifies: boolean;
}

/** One machine-minted taint record (Plan 9), on the wire. */
export interface DerivedLabelWire {
  path: string;
  /** The watermark of the session that wrote the file. */
  level: string;
  bindings: string[];
  /** WHICH session wrote it, and with WHAT — §8 requires the release UI show what
   * fed the artifact. */
  sessionKey: string;
  tool: string | null;
  updatedAt: number;
  /** The level a future session ACTUALLY classifies this path at. Differs from
   * `level` when the catalog is stricter, or when a human's exact-path label
   * overrides the taint — which is the §8 release act, and the UI must show that
   * it took effect. */
  effective: string;
  /** True when an exact-path human label is overriding this record. */
  overridden: boolean;
}

/** THE LABELING ACT (confidentiality.md §6 item 2, Plan 6) — and the only
 * producer of `any-model` in the system: the default-secret catalog
 * yields public/strict only, deliberately, because the level encodes a
 * clearance decision (ZDR/BAA/local model) no code can observe. */
export interface SetPathLabelOpRequest extends BaseRequest {
  op: "setPathLabel";
  /** Absolute path (or `~/…`) of the file or directory to label. */
  path: string;
  /** "public" | "any-model" | "local-model" | "no-model". Anything else is REJECTED,
   * not coerced — a labeling act is explicit or it is not an act. */
  confidentiality: string;
  /** Bound destinations this datum may be released to (§2). */
  bindings?: string[];
  /** Cover descendants (default true). */
  recursive?: boolean;
}

export interface SetPathLabelResultWire {
  path: string;
  level: string;
  bindings: string[];
  recursive: boolean;
  declassifies: boolean;
}

export interface RemovePathLabelOpRequest extends BaseRequest {
  op: "removePathLabel";
  path: string;
}

export interface RemovePathLabelResultWire {
  removed: boolean;
}

export interface PathLabelsOpRequest extends BaseRequest {
  op: "pathLabels";
}

/**
 * THE DERIVED-LABEL ACT (confidentiality.md §4 bullet 2 + §8, Plan 9): a session
 * is about to WRITE a file. If that session is HIGH — it has read secret content
 * into T-LLM's context — the file it writes may be derived from that content, so
 * the arbiter records an on-disk label at the watermark. This is what makes the
 * watermark survive the session: without it, the NEXT session reads the file, the
 * catalog finds no match, and it classifies PUBLIC.
 *
 * Asked at the response-side `tool_use` hook, BEFORE the bytes land (§4: labeled
 * "before fs-sync exposes them anywhere public"). Inert for a public session and
 * while the axis is OFF; a throw/timeout is fail-closed at the CALLER (the write
 * is denied — "we could not check" must never resolve to "write it unlabeled").
 */
export interface LabelWrittenPathOpRequest extends BaseRequest {
  op: "labelWrittenPath";
  /** The session doing the writing — its watermark is the level recorded. */
  sessionKey?: string;
  /** The absolute HumanView path being written. */
  path: string;
  /** The tool doing the writing (`Write`, `Edit`, …) — provenance for §8's UI. */
  tool?: string;
}

export interface LabelWrittenPathResultWire {
  /** Did this write mint (or raise) a derived label? False for a public session,
   *  an OFF axis, or a path already at/above the watermark. */
  labeled: boolean;
  /**
   * The session is HIGH and this write could NOT be labeled — the caller MUST
   * fail closed (deny the write).
   *
   * Today the only cause is a path with no stable identity (a relative one: we
   * will not guess an absolute path on the model's behalf). It is a SEPARATE flag
   * from `labeled` because the two falsy cases are opposites: "nothing to persist"
   * (a public session — proceed, byte-identical to today) and "we could not
   * persist" (a high session — an unlabeled write from it IS the laundering hole).
   * Collapsing them into one boolean is how this ships silently fail-open.
   */
  refused: boolean;
  /** The level a FUTURE session will now classify this path at — the point of
   *  the whole plan, and what the caller emits for the dashboard. */
  level: string;
  /** ALWAYS EMPTY on a derived row: a machine may taint, never grant a release
   *  (see derived-labels.ts). Present so the shape matches a user label. */
  bindings: string[];
  reason: string;
}

/** The human's CLEAR act on a derived taint record (§8 — declassification must
 *  be first-class, or utility dies by over-taint). */
export interface RemoveDerivedLabelOpRequest extends BaseRequest {
  op: "removeDerivedLabel";
  path: string;
}

export interface RemoveDerivedLabelResultWire {
  removed: boolean;
}

/** §3.3 RUNG 3 — the IN-CONTEXT READ (Plan 8). An EXPLICIT act: raw content
 * enters T-LLM's context only because the model ASKED, by name, and the arbiter
 * ALLOWED. Split from `inspect_symbol` (rung 2) so the escalation is deliberate,
 * named, logged, and refusable. Every allowed read HIGH-WATERMARKS the session. */
export interface DeclassifySymbolOpRequest extends BaseRequest {
  op: "declassifySymbol";
  symbol: string;
  /** REQUIRED in practice: a read that cannot be watermarked cannot be confined,
   * so the arbiter refuses without one. */
  sessionKey?: string;
  /** Free-text justification from the model, recorded on the approval. */
  reason?: string;
}

export interface DeclassifySymbolResultWire {
  /** The raw content — ONLY when allowed. null on any refusal. */
  value: string | null;
  allowed: boolean;
  /** true ⇒ a human decision is what stands in the way (§9 rule 2's session
   * half). false on a HARD refusal — an untrusted datum or a strict one, which
   * no approval opens. */
  requiresApproval: boolean;
  reason: string;
  /** The level the session was raised to, when allowed. */
  watermark?: string;
}

/** What a HIGH session may still do (§4). Consulted IN ADDITION to the
 * per-symbol egress gate — a PARAPHRASE carries no symbol, so the per-symbol
 * gate is structurally blind to the very leak the watermark exists to catch. */
export interface SessionEgressDecisionOpRequest extends BaseRequest {
  op: "sessionEgressDecision";
  sessionKey?: string;
  boundary: "network" | "shell" | "filesystem";
  destination?: string;
  /** For `shell`: does the world have network? An AgentShell (net off) is not
   * an egress and is not gated. */
  netEnabled?: boolean;
}

export interface SessionEgressDecisionResultWire {
  allow: boolean;
  requiresApproval: boolean;
  reason: string;
  /** Decision provenance (rule-ref.ts): the session rule, or `verdict:<id>`
   *  when a human answer decided. */
  ruleRef?: RuleRef;
  /** The Approvals row this refusal filed or bumped (confidentiality.md §4,
   *  "The human half", 2026-10-11): rides to the deny event as
   *  `policy.approvalId`. Absent on an allow, a human Block, and a refusal
   *  no human can answer. */
  approvalId?: string;
}

/** confidentiality.md §4, "What Allow once means for a command": the
 * kernel guard's question at a tool call's shell exec (the call root), asked
 * before it lets the exec go. In a HIGH session the arbiter records the
 * session's taint rows on the process and answers `holder`. Human plane
 * only (from the data socket: `holder: false`). */
export interface SessionExecRootOpRequest extends BaseRequest {
  op: "sessionExecRoot";
  procKey: string;
  session?: string;
}

export interface SessionExecRootResultWire {
  holder: boolean;
  level?: string;
  reason: string;
}

/** confidentiality.md §4, "Without the guard": the session's kernel guard
 * announces that it holds the session's processes. Human plane only. */
export interface GuardAttachOpRequest extends BaseRequest {
  op: "guardAttach";
  sessionKey: string;
}

export interface GuardAttachResultWire {
  attached: boolean;
  reason?: string;
}

/** The §4 verbatim-leak TRIPWIRE (confidentiality.md §4 defense-in-depth). The
 * net-proxy hands the arbiter the outbound surfaces (url/headers/body) and the
 * destination; the arbiter scans them against its known secret VALUES and
 * reports any that appear verbatim, bound for a host they were never released
 * to. This backs the symbol gates — it is NOT the guarantee (a paraphrase
 * carries neither symbol nor verbatim bytes). Fires a block on a POSITIVE hit
 * only; an axis-off / empty-secret / error result is an inert no-op. */
export interface EgressFingerprintScanOpRequest extends BaseRequest {
  op: "egressFingerprintScan";
  /** The outbound surfaces to scan. `where` is url|header|body for the audit. */
  surfaces: { where: string; text: string }[];
  /** The destination host — a secret at its own bound host is NOT a leak. */
  destination: string;
  /** The asking session's logins (secret-discovery.ts `SessionLogins`:
   *  `home`, `target`, `ullmBinary`, `otherLoginsRaw`, `loginEnv`), sent by
   *  the session's net-proxy: the registered rows of the login files that
   *  session leaves raw are not scanned for it (secret-discovery.md §1.10).
   *  Login files only; absent or malformed, nothing is exempt. */
  sessionLogins?: SessionLoginsWire;
}

/** A session's logins on the wire (secret-discovery.ts `SessionLogins`). */
export interface SessionLoginsWire {
  home: string;
  target?: string;
  ullmBinary?: string;
  otherLoginsRaw?: boolean;
  loginEnv?: Record<string, string>;
}

/** A placeholder the agent's shell emptied (confidentiality.md §7, "A
 * placeholder the agent's shell would expand"). The net-proxy finds text
 * shaped like a labelled placeholder that lost its `$MDU` (`:nomodel_…[h]`,
 * and zsh's `nymodel_…` / `ocalmodel_…`) and asks which of the names it
 * reconstructs are rows of the symbol table, so free text that only looks
 * alike is never refused. Names only: never a value, a label or a binding.
 * Result: `StrippedPlaceholdersResultWire`. */
export interface StrippedPlaceholdersOpRequest extends BaseRequest {
  op: "strippedPlaceholders";
  /** Complete `$MDU:` names (at most STRIPPED_PLACEHOLDERS_MAX). */
  candidates: string[];
  /** Attribution only. */
  sessionKey?: string;
}

/** The most names one `strippedPlaceholders` ask may carry. */
export const STRIPPED_PLACEHOLDERS_MAX = 64;

export interface StrippedPlaceholdersResultWire {
  /** The candidates that name a secret-labelled row (the row's level, never
   *  the name's marker), in the order asked. */
  found: string[];
  /** The deciding rule when `found` is not empty. */
  ruleRef?: RuleRef;
}

/** A refusal of the DevTools relay's, kept for the browser agent's next
 * model call (relay-notices.ts; devtools-relay.md §3.4). Structured names
 * only, checked by `parseRelayNotice`: never free text, never a value. On
 * the data socket. Result: `{ queued: true }`. */
export interface RelayNoticeOpRequest extends BaseRequest {
  op: "relayNotice";
  notice: RelayNoticeWire;
  /** The session the relay was started for (the launch's scope id). */
  sessionKey?: string;
}

/** The session's pending relay refusals, CLEARED by the take (each is told
 * once). The egress proxy asks it per model-service Chat Completions call.
 * Result: `TakeRelayNoticesResultWire`. */
export interface TakeRelayNoticesOpRequest extends BaseRequest {
  op: "takeRelayNotices";
  sessionKey?: string;
}

export interface TakeRelayNoticesResultWire {
  /** Oldest first; empty when none wait. */
  notices: RelayNoticeWire[];
}

/** Whether a placeholder's BASE (`$MDU:kind[code]`, no field path) names a
 * row, its own or a field's (symbol-table.ts `placeholderBaseKnown`). The
 * DevTools relay asks it on the key that closes a typed placeholder's code,
 * and refuses that key when the answer is false (devtools-relay.md §3.3).
 * Names only, never a value. Human plane only (the relay's release gate and
 * values are there; the agent world gets the same bit from
 * `desymbolizationDecision` anyway, and from no new op). Anything but a base
 * is refused. Result: `PlaceholderKnownResultWire`. */
export interface PlaceholderKnownOpRequest extends BaseRequest {
  op: "placeholderKnown";
  base: string;
}

export interface PlaceholderKnownResultWire {
  known: boolean;
}

export interface EgressFingerprintScanResultWire {
  /** True iff at least one secret appeared verbatim, bound for a non-released
   *  destination. The net-proxy blocks the request when so. */
  tripped: boolean;
  /** The hits, carrying the SYMBOL name + level + surface — NEVER the value
   *  (this result rides an observability event and must not itself leak). */
  hits: { symbol: string; level: string; where: string }[];
}

/** The session's floating label — the dashboard's watermark surface. */
export interface SessionStateOpRequest extends BaseRequest {
  op: "sessionState";
  sessionKey?: string;
}

export interface SessionStateResultWire {
  sessionKey: string;
  confidentiality: string;
  untrustedTainted: boolean;
  bindings: string[];
  /** Has this session read secret content into context? */
  high: boolean;
}

export interface PathLabelsResultWire {
  labels: PathLabelWire[];
}

export type ArbiterRequest =
  | DeclassifySymbolOpRequest
  | SessionEgressDecisionOpRequest
  | SessionExecRootOpRequest
  | GuardAttachOpRequest
  | EgressFingerprintScanOpRequest
  | StrippedPlaceholdersOpRequest
  | RelayNoticeOpRequest
  | TakeRelayNoticesOpRequest
  | PlaceholderKnownOpRequest
  | SessionStateOpRequest
  | SetPathLabelOpRequest
  | RemovePathLabelOpRequest
  | PathLabelsOpRequest
  | LabelWrittenPathOpRequest
  | RemoveDerivedLabelOpRequest
  | SymbolizeRequest
  | SymbolizeDerivedRequest
  | DesymbolizeRequest
  | ResolveRequest
  | SymbolProvenanceRequest
  | ClassifyOpRequest
  | PingRequest
  | HelloRequest
  | HandlingPromptRequest
  | ToolSurfaceRequest
  | GateSurfaceRequest
  | RecordToolCallRequest
  | DesymbolizationDecisionOpRequest
  | FsPathDecisionOpRequest
  | FileUploadDecisionOpRequest
  | ClassifyExecOpRequest
  | ResolveExecArgvOpRequest
  | ExecGateOpRequest
  | ExecDecisionForOpRequest
  | EscalateExecOpRequest
  | ReportExecCleanVerdictOpRequest
  | ExecCleanVerdictForOpRequest
  | ReportExecTwinsOpRequest
  | ExecTwinsForOpRequest
  | PathLevelOpRequest
  | PathLevelsOpRequest
  | MovePageLabelsOpRequest
  | WhyPathOpRequest
  | WhyHostOpRequest
  | WhySymbolOpRequest
  | EnvSourcesOpRequest
  | SshAgentPolicyOpRequest
  | ReaderProgramOpRequest
  | VerifyEventsOpRequest
  | ProtectPathsOpRequest
  | GuardSettingsOpRequest
  | GitHistoryLocksOpRequest
  | RegisterRepositoryOpRequest
  | CacheSealsOpRequest
  | SealCacheEntriesOpRequest
  | BeginLaunchOpRequest
  | EndLaunchOpRequest
  | HumanPlaneStatusOpRequest
  | ConsumerPacksOpRequest
  | PolicySnapshotOpRequest
  | NetConnectAllowOpRequest
  | ModelEndpointsOpRequest
  | SetSessionUpstreamRequest
  | ClaimCleanReporterRequest
  | SessionUpstreamOpRequest
  | TestFlowOpRequest
  | EgressApprovalsRequest
  | ResolveEgressApprovalRequest
  | ForgetEgressApprovalRequest
  | SetSessionPostureRequest
  | SetSessionSpecRequest
  | SymbolShapeRequest
  | SetSessionRelayRequest
  | SessionRelayOpRequest
  | NoteReserveBlockRequest
  | ReserveBlockOpRequest
  | RecordForwardedClearRequest
  | ForwardedClearRequest
  | RecordForwardedPlaceholdersRequest
  | ForwardedPlaceholdersRequest
  | EmitRequest
  | EventsRequest
  | SessionsRequest
  | DeleteSessionRequest
  | SubscribeRequest
  | TaintProcessOpRequest
  | TaintProcessSecretOpRequest
  | ProcessSecretTaintOpRequest
  | RecordCallRootOpRequest
  | CallTaintOpRequest
  | RecordCallCommandOpRequest
  | RecordEgressRefusalOpRequest
  | RegisterMcpServersOpRequest
  | RegisterWireReleaseOpRequest
  | RegisterAuthGrantOpRequest
  | McpServerTaintOpRequest
  | DecideSecretOpenOpRequest
  | DecideProtectedWriteOpRequest
  | RecordExecRootOpRequest
  | ScanSecretValuesOpRequest
  | DocumentTextOpRequest
  | FilterPromptOpRequest
  | PromptFiltersOpRequest
  | PromptFilterPacksOpRequest
  | PromptExceptionsOpRequest
  | PromptPackEditOpRequest
  | ResolvePromptHoldOpRequest
  | LetPromptFindingThroughOpRequest
  | PromptHoldsOpRequest
  | TaintedProcessBindingsOpRequest
  | HolderSourceBindingOpRequest
  | SessionSecretTaintOpRequest
  | SecretTaintedProcessesOpRequest
  | LabelWrittenPathTaintedOpRequest
  | DerivedLabelsSinceOpRequest
  | LabelRootsSinceOpRequest
  | LabelledLevelOpRequest
  | SessionPathLabelOpRequest
  | ClearSessionPathLabelsOpRequest
  | FollowDerivedLabelOpRequest
  | ProcessLineageOpRequest
  | RecordProcessFlowOpRequest
  | RecordAgentFlowOpRequest
  | AgentReceiptTaintOpRequest
  | IsProcessTaintedOpRequest
  | TaintFileOpRequest
  | FileTrustOpRequest
  | RegisterSecretOpRequest
  | RegisterEnvSecretsOpRequest
  | EnvSecretNamesOpRequest
  | SecretRegistryOpRequest
  | DiscoverSecretsOpRequest
  | ScanSecretHistoryOpRequest
  | SuggestPolicyOpRequest
  | PolicySuggestionsOpRequest
  | ApplySuggestionOpRequest
  | DismissSuggestionOpRequest
  | ModelSuggestPreviewOpRequest
  | ModelSuggestOpRequest
  | ConfidentialityStateOpRequest
  | PolicyDocumentOpRequest
  | ApplyPolicyDocumentOpRequest
  | MintUserRuleOpRequest
  | ExportDbLabelsOpRequest
  | PolicyProposeOpRequest
  | PolicyProposalsOpRequest
  | PolicyChangesOpRequest
  | ResolvePolicyProposalOpRequest
  | UndoPolicyChangeOpRequest
  | PolicyExplainOpRequest
  | PolicySchemaOpRequest
  | PolicyPreviewOpRequest;

// ── policy document ops (policy-surface.md §2.1, stage 5a) — ADMIN-ONLY ─
// The arbiter is the single writer of policy.yaml. `policyDocument` reads the
// file as it is on disk (leniently, so an invalid file can be shown) plus the
// document in force and the file status; the three writers validate strictly,
// write atomically, recompile + swap, and audit (`policy_change`).

// `netConnectAllow` (policy-surface.md §2.3, stage 4b): the law's
// reachability allowances as connect-guard specs (`proto:host:port`). DATA
// plane: the launcher reads it at launch and appends the specs to its guard
// set WITHOUT dropping the permissive fallback. Fail-soft on the launcher's
// side: unreachable ⇒ no extra allow (tighter, never looser).
export interface NetConnectAllowOpRequest extends BaseRequest {
  op: "netConnectAllow";
}

export interface NetConnectAllowResult {
  specs: string[];
}

// `modelEndpoints` (plan 11 D5): the declared model endpoints of the law in
// force (policy.yaml `models:`, defaults applied), for inspect-mcp's routing
// and the launcher's confine ports. Data plane, read-only: the list carries
// no secret (a bearer token is named by its environment variable only).
export interface ModelEndpointsOpRequest extends BaseRequest {
  op: "modelEndpoints";
}

export interface ModelEndpointWire {
  name: string;
  url: string;
  wire: "anthropic" | "openai-chat";
  model?: string;
  local: boolean;
  tokenEnv?: string;
  /** policy.yaml `helper: true`: the quarantined helper's model. Present only
   *  when true, so a client that predates it sees the same list as before. */
  helper?: true;
  /** policy.yaml `allow_plain_http: true` (plan 12 D2): the helper may reach
   *  this entry over plain http on another machine. Present only when true;
   *  a helper that never sees it keeps refusing (fail-closed). */
  allowPlainHttp?: true;
  /** policy.yaml `tls:` (plan 12 D3): absolute paths and pins, only the
   *  fields given. The paths are not secret; the key FILE is masked in the
   *  agent's world, so the helper gets its bytes from the launcher. */
  tls?: { caFile?: string; pinSha256?: readonly string[]; clientCert?: string; clientKey?: string };
  /** policy.yaml `perimeter.networks` (plan 12 D4), on a `local: true` entry
   *  on another machine only: every address the name resolves to must be
   *  inside one of these CIDRs when a client connects. */
  perimeter?: readonly string[];
  /** The host is (under) one of `perimeter.domains` (plan 12 D4): words only. */
  orgDomain?: true;
  /** Plan 12 D5: the administrator's file that set this entry. */
  adminFile?: string;
  /** Plan 12 D5: set by the administrator and locked (the user may remove
   *  it, not change it). */
  locked?: true;
}

/** Plan 12 D5: the administrator's layer in force, when there is one. */
export interface AdminLayerWire {
  files: string[];
  locked: boolean;
  /** The user's entries the administrator's layer keeps out of force. */
  conflicts: string[];
  /** A changed layer that could not be read (the one before stays in force). */
  refused: string[];
}

export interface ModelEndpointsResult {
  endpoints: ModelEndpointWire[];
  /** Plan 12 D5: present only when an administrator's layer is in force, or
   *  a re-read of it was refused. */
  admin?: AdminLayerWire;
}

// `setSessionUpstream` / `sessionUpstream` (plan 11 phase 3): which declared
// model the session's MAIN conversation (the T-LLM) is sent to. The launcher
// records it once per launch, before any service starts, from the one place
// that decides it (a user-set ANTHROPIC_BASE_URL equal to a declared
// `wire: anthropic` entry keeps the model proxy in front of that entry).
// Rung 3 (`declassify_symbol`) reads the binding: a `local-model` symbol may
// enter the conversation only when the bound entry is `local: true` in the
// law IN FORCE, looked up by name at decision time.
//
// DATA plane, and therefore reachable by the agent's own processes. What they
// must not do is claim a local main model for a session whose conversation
// goes to an outside vendor. Three rules close that: the binding is
// BIND-ONCE (a bound session cannot be re-bound to a different entry), a
// session that has already carried traffic cannot be bound at all, and the
// binding is PERSISTED in mandu.db, so an arbiter restart does not reopen the
// window. The launcher binds every session it starts (`endpoint: null` for
// the default vendor), so the first binding is always the launcher's.
export interface SetSessionUpstreamRequest extends BaseRequest {
  op: "setSessionUpstream";
  sessionKey: string;
  /** The `models:` entry name the conversation is sent to, or null for the
   *  agent's default vendor (an outside model). */
  endpoint: string | null;
  /** Free-text provenance for the log (e.g. "launcher"). */
  requestedBy?: string;
  /** exec-routing.md §8.5.3: the launcher will run a guard that hosts the
   *  clean box, so its reporter token may be claimed. Honored only on the
   *  FRESH bind. */
  cleanReporter?: boolean;
}

export interface SessionUpstreamOpRequest extends BaseRequest {
  op: "sessionUpstream";
  sessionKey: string;
}

export interface SessionUpstreamResult {
  sessionKey: string;
  /** The bound entry name; null = the default vendor, or no binding. */
  endpoint: string | null;
  /** Where the main model runs, from the law in force: `local` only when the
   *  bound entry is declared `local: true`; an unbound session, a null
   *  binding and a name no longer declared are all `external`. */
  location: "local" | "external";
  /** Has the session been bound at all? */
  bound: boolean;
  /** `true` when the session's clean-verdict reporter is claimable or
   *  claimed (not revoked); absent otherwise. exec-routing.md §8.5.3. */
  cleanReporter?: true;
}

// `testFlow` (policy-surface.md §4 "Test a flow", §5 "Tester ≡
// gates"): ask the REAL gates what would happen to a datum from `source`
// headed for `destination`, without doing it — the inbound classification
// (would it be masked?) and the egress decision for a SYNTHETIC symbol entry
// built from that classification, run through the very same composition the
// live gate uses (standing verdict → lockdown → user rules → disposition →
// built-in), with every side effect (queue, hit counts) off. DATA plane: a
// read. `stage` names the layer that decided.
export type DesymStage = "verdict" | "lockdown" | "user-rule" | "disposition" | "built-in";

export interface TestFlowOpRequest extends BaseRequest {
  op: "testFlow";
  /** The datum's provenance: tool (default WebFetch), field (default: the
   *  tool's whole result), origin (URL / path / channel), and optionally the
   *  tool_use params the proxy would have passed (a schema keys a field's
   *  category off `params.<x>`, e.g. WebFetch.content off params.url). Absent
   *  params are derived from the origin: a URL ⇒ { url }, else
   *  { file_path, path }. */
  source?: { tool?: string; field?: string; origin?: string; params?: Record<string, string> };
  /** Where it would go. Absent with no boundary ⇒ inbound only. */
  destination?: string;
  boundary?: "network" | "filesystem" | "shell" | "model_context";
  asCommand?: boolean;
  /** Force the probe's confidentiality level (default: what classify derived). */
  level?: string;
  /** Probe the law in force WITH these PolicyEdits applied (policy-agent-
   *  surface.md §5.2, the Describe box's "Try it"). Nothing is written: the
   *  hypothetical law exists only for this synchronous call. Invalid edits
   *  answer an error. */
  withEdits?: unknown;
}

export interface TestFlowResult {
  inbound: ClassifyResult;
  probe: { tool: string; field: string | null; origin: string | null; level: string; integrity: "trusted" | "untrusted" };
  /** null when no destination/boundary was asked, or when the engine cannot
   *  probe (an injected engine without desymbolizationDecisionWith). */
  egress: { decision: DesymbolizationDecision; stage: DesymStage } | null;
  /** Present when the source is a registered FILE read (`tool: Read`, a path
   *  origin, no forced other level): how many placeholders a real send of the
   *  file carries (every active registration's twin symbols). `egress` was
   *  then asked once per placeholder, keyed on it, so a human's standing
   *  answer about the file counts, and is the most restrictive answer
   *  (tour 1). Absent: one synthetic probe symbol, which no answer covers. */
  placeholders?: number;
  /** Set when `egress` is null for a reason worth telling the human. */
  note?: string;
  /** Present when the tested source is a FILESYSTEM PATH: the confidentiality
   *  derivation for that path, the same one `pathLevel` answers (level,
   *  bindings, the deciding `rule`; see {@link PathLevelOpResult}). `axis:false`
   *  = the confidentiality axis is OFF, so the `public` level is not a finding
   *  about the path. `outranked` = pattern labels that also match the path,
   *  lost on specificity to the literal directory label that decided, and are
   *  STRICTER than it (confidentiality.md §6.1). Observability only. */
  pathLabel?: TestFlowPathLabel;
}

export interface TestFlowPathLabel {
  path: string;
  level: string;
  bindings: string[];
  axis: boolean;
  rule: string | null;
  outranked: Array<{ pattern: string; level: string }>;
}

export interface PolicyDocumentOpRequest extends BaseRequest {
  op: "policyDocument";
}

export interface PolicyFileStatusWire {
  path: string | null;
  found: boolean;
  valid: boolean;
  problems: string[];
  loadedAt: number | null;
  refusedAt: number | null;
}

export interface PolicyDocumentResult {
  status: PolicyFileStatusWire;
  /** The document in force (null = built-ins only). */
  inForce: unknown;
  /** The version of `inForce` (policy-document-store.ts `lawHashOf`): a
   *  whole document built from it is applied with it
   *  (`applyPolicyDocument.lawHash`), and refused as stale once the law in
   *  force is another one. Keyed per arbiter process (not stable across a
   *  restart). Absent from an arbiter that predates it. */
  lawHash?: string;
  /** The version of each item of `inForce`, `section → key → version`
   *  (policy-document-store.ts `itemVersionOf`, the same key as `lawHash`):
   *  a typed edit that carries fields over from this read names the items
   *  it read (`policyPropose.basedOn`). Absent from an arbiter that
   *  predates it. */
  itemVersions?: Record<string, Record<string, string>>;
  /** The version of an item `inForce` does not have (`itemVersionOf(null)`,
   *  the same key): a typed edit that CREATES an item where this read found
   *  none names it with this, and is refused `stale` once someone else made
   *  it (Settings › Sensitivity labels mapping a label, the file browser's
   *  first rule on a path). Absent from an arbiter that predates it. */
  absentVersion?: string;
  /** The file on disk right now: raw text + lenient parse + its problems, and
   *  `warnings` (Plan 13 D8): advice on a valid document, e.g. a reader that
   *  runs any code. */
  onDisk: { text: string | null; parsed: unknown; problems: string[]; warnings: string[]; textRebuilt?: true };
  /** Plan 12 D5: the administrator's layer, when one is in force: its files,
   *  the lock, its `models:` entries as written (each with its `file`) and
   *  its `perimeter:`. */
  admin?: { files: string[]; locked: boolean; models: Array<Record<string, unknown>>; perimeter: unknown; perimeterFile: string | null; conflicts: string[]; refused: string[] };
  /** Plan 15 §13.7 item 4, the DATA socket only: each prompt exception's
   *  `match` (in `inForce`, `onDisk.parsed`, the admin layer's prompt
   *  filters, and the `match:` values of the file's text) is
   *  `PROMPT_PATTERN_PLACEHOLDER` with `patternHidden: true` beside it.
   *  `onDisk.textRebuilt`: the text could not be edited in place and was
   *  rebuilt from the redacted parse (comments lost). The human socket and
   *  the admin channel answer in full. */
  patternsHidden?: true;
}

export interface ApplyPolicyDocumentOpRequest extends BaseRequest {
  op: "applyPolicyDocument";
  /** The whole document (replaces the file). */
  document: unknown;
  /** Required: the `lawHash` of the `policyDocument` read the document was
   *  built from. The arbiter refuses the apply as stale when the law in
   *  force is no longer that law (policy-surface.md §8.4.6): writing the
   *  document would undo the change that landed in between. */
  lawHash: string;
  requestedBy?: string;
}

export interface ApplyPolicyDocumentResult {
  path: string;
  status: PolicyFileStatusWire;
}

export interface MintUserRuleOpRequest extends BaseRequest {
  op: "mintUserRule";
  rule: {
    kind: "release";
    from?: { host?: string };
    to: { host: string };
    mode: "allow" | "block" | "audit" | "off";
    reason?: string;
    by?: string;
    expires?: string | null;
  };
  requestedBy?: string;
}

export interface MintUserRuleResult {
  id: string;
  path: string;
  status: PolicyFileStatusWire;
}

export interface ExportDbLabelsOpRequest extends BaseRequest {
  op: "exportDbLabels";
  requestedBy?: string;
}

export interface ExportDbLabelsResult {
  added: number;
  path: string;
  status: PolicyFileStatusWire;
}

// ── policy agent surface (policy-surface.md §8.4.2) ────────────────────
// Any client may TIGHTEN the law; only a human may RELAX it. `policyPropose`
// (data plane) applies a tightening at once and files anything else as a
// proposal; `resolvePolicyProposal` and `undoPolicyChange` are ADMIN-ONLY.
// Every `reason` is UNTRUSTED text (§3.6): stored as written, never rendered
// as anything but the client's words, never in `policyExplain`.

/** One row of a tighten/relax delta (arbiter/policy/policy-delta.ts). */
export interface PolicyDeltaChangeWire {
  facet: string;
  direction: "relax" | "tighten";
  subject: string;
  detail: string;
  /** Plan 15 §13.7 item 4, the DATA socket only: a prompt exception's line,
   *  its pattern in `detail` replaced by `PROMPT_PATTERN_PLACEHOLDER`. An
   *  exception edit in `edits` (policyProposals, policyChanges) carries the
   *  placeholder as its `match` and `patternHidden: true` the same way. */
  patternHidden?: true;
}

export interface PolicyProposeOpRequest extends BaseRequest {
  op: "policyPropose";
  /** A list of typed edits (arbiter/policy/policy-edit.ts `PolicyEdit`). */
  edits: unknown;
  /** Why: the client's words, capped at 280 characters. UNTRUSTED. */
  reason?: string;
  /** The calling agent session (attribution + the per-session caps). */
  sessionKey?: string;
  /** Admin channel only: who asked (the data plane is always `agent:<sessionKey>`). */
  requestedBy?: string;
  /** The items the edits were built from, each with the version it had
   *  when read (policy-surface.md §8.4.6 "An item-level version"): an
   *  edit that carries fields over from a read (Settings › Models' update
   *  keeps an entry's `tls`) names the entry, and is refused `stale`
   *  (`changed` naming it, nothing written or filed) once that item is
   *  another. A proposal filed keeps the precondition: approving it later
   *  refuses the same way (`ResolvePolicyProposalResult.stale`). At most 64. */
  basedOn?: PolicyItemVersionWire[];
}

/** One item of the law and its version (policy-document-store.ts
 *  `itemVersionOf`; `policyDocument.itemVersions`, the snapshot's
 *  `document.modelVersions`). `section` + `key` are the identity Undo uses:
 *  `models` + a model's name, `user_rules` + a rule's id, `paths` + a lock's
 *  path, ... */
export interface PolicyItemVersionWire {
  section: string;
  key: string;
  version: string;
}

export type PolicyProposeResult =
  | { applied: true; changeId: string | null; delta: PolicyDeltaChangeWire[]; note?: string }
  | { applied: false; proposalId: string; relaxes: PolicyDeltaChangeWire[]; why: "relaxes" | "tightening-cap"; duplicate?: boolean }
  /** `changed` (with `stale`, from `basedOn`): the items that are no longer
   *  the version the edits were built from, `section key` each. */
  | { applied: false; refused: "invalid" | "stale" | "proposal-cap"; problems: string[]; changed?: string[] };

export interface PolicyProposalWire {
  id: string;
  edits: unknown[];
  /** UNTRUSTED: the requesting client's words. */
  reason: string | null;
  requestedBy: string;
  sessionKey: string | null;
  relaxes: PolicyDeltaChangeWire[];
  tightens: PolicyDeltaChangeWire[];
  status: "pending" | "approved" | "denied" | "superseded";
  createdAt: number;
  resolvedAt: number | null;
  resolvedBy: string | null;
  changeId: string | null;
  supersededBy: string | null;
  /** A HELD DISK CHANGE (policy-surface.md §8.4.6): policy.yaml changed on
   *  disk and relaxes the law, so it waits here with no edits; approving loads
   *  the file's bytes with this sha256 (a file that moved on is judged afresh).
   *  null (or absent, from an older arbiter) for an edit proposal. */
  diskHash?: string | null;
  /** A held disk change's text as it was held (null: the change removed the
   *  file). ADMIN channel only: declining restores policy.yaml to the law in
   *  force (policy-restore.ts), and this is where the hand edit is kept. */
  diskText?: string | null;
  /** "suggestion": filed by Mandu's scan (plan 14 §5.1; `policySuggestions`
   *  gives the review's view). Absent from an older arbiter: a proposal. */
  kind?: "proposal" | "suggestion";
  /** A suggestion's dedup key; null for a proposal. */
  findingKey?: string | null;
  /** A suggestion's review facts (no value); null for a proposal. */
  suggestion?: Omit<Suggestion, "edits" | "findingKey"> | null;
}

export interface PolicyProposalsOpRequest extends BaseRequest {
  op: "policyProposals";
  status?: "pending" | "approved" | "denied" | "superseded";
  /** Default "proposal": the Inbox's cards. Suggestions are read with
   *  `policySuggestions` (or `kind: "suggestion"` here). */
  kind?: "proposal" | "suggestion";
}

export interface PolicyProposalsResult {
  proposals: PolicyProposalWire[];
}

/** One item a recorded change touched (policy-edit.ts RevertItem), named. */
export interface PolicyChangeRuleWire {
  /** The Rules page row ids the item compiles to (compiled-policy.ts panelRowIds). */
  rowIds: string[];
  /** The item did not exist before the change. */
  added: boolean;
  /** The change removed the item. */
  removed: boolean;
  /** Its value now is still what the change left (no later edit). */
  current: boolean;
}

export interface PolicyChangeWire {
  id: string;
  /** How it arrived (policy-proposals.ts ChangeVia); the last five are
   *  writes outside the policy surface (dashboard.md §4.25j). */
  via: "agent-tighten" | "tighten" | "proposal" | "undo" | "disk" | "apply" | "mint-rule" | "export-labels" | "pin-reader" | "move-labels";
  requestedBy: string;
  sessionKey: string | null;
  edits: unknown[];
  delta: PolicyDeltaChangeWire[];
  proposalId: string | null;
  createdAt: number;
  undoneAt: number | null;
  undoneBy: string | null;
  /** Undo is available: not undone, and not itself an undo. */
  undoable: boolean;
  /** The proposal's original requester (`agent:<session>`, `rules-page`,
   *  `assistant`, `mandu:scan` for an applied suggestion) whenever the change
   *  carries a `proposalId`; when `via` is "proposal", `requestedBy` is then the approver.
   *  Absent on arbiters predating it (dashboard.md §4.25i). */
  proposedBy?: string | null;
  /** The rules the change touched, as the Rules page names its rows, and
   *  whether each still holds what the change left (`current`); absent on
   *  arbiters predating it (dashboard.md §4.25i). */
  rules?: PolicyChangeRuleWire[];
}

export interface PolicyChangesOpRequest extends BaseRequest {
  op: "policyChanges";
  limit?: number;
}

export interface PolicyChangesResult {
  changes: PolicyChangeWire[];
}

export interface ResolvePolicyProposalOpRequest extends BaseRequest {
  op: "resolvePolicyProposal";
  proposalId: string;
  verdict: "approved" | "denied";
  requestedBy?: string;
}

export interface ResolvePolicyProposalResult {
  proposal: PolicyProposalWire;
  /** approved: the change it became. */
  changeId?: string;
  /** approved, but the law had moved and approving would now give up MORE:
   *  the old proposal is `superseded` and this one waits instead. */
  refiled?: PolicyProposalWire;
  /** approved, but an item the proposal was built from (its `basedOn`)
   *  changed since: nothing was written, the proposal is closed
   *  `superseded` by `mandu:stale`, and these are the items, `section key`
   *  each (policy-surface.md §8.4.6 "An item-level version"). */
  stale?: string[];
  /** denied, a held disk change: policy.yaml was written back to the law in
   *  force (false: the file had moved on, and the newer content was judged
   *  as a fresh edit; or the write failed and the arbiter retries). */
  restored?: boolean;
}

export interface UndoPolicyChangeOpRequest extends BaseRequest {
  op: "undoPolicyChange";
  changeId: string;
  requestedBy?: string;
}

export interface UndoPolicyChangeResult {
  /** The change that undid it (recorded like any other, via "undo"). */
  changeId: string;
  undone: string;
  delta: PolicyDeltaChangeWire[];
}

/** `policyPreview` (§5.2): what an edit list WOULD do to the law in force,
 *  nothing written. Data plane (a read). `perEdit[i].loosens` is the delta of
 *  edit i alone; an edit that cannot be judged alone (it names a list an
 *  earlier edit creates) is marked as loosening, the safe label. */
export interface PolicyPreviewOpRequest extends BaseRequest {
  op: "policyPreview";
  edits: unknown;
}

export type PolicyPreviewResult =
  | { ok: true; relaxations: PolicyDeltaChangeWire[]; tightenings: PolicyDeltaChangeWire[]; perEdit: Array<{ loosens: boolean }> }
  | { ok: false; problems: string[] };

/** `policySchema` (§4.3): the JSON Schema of a PolicyEdit list a MODEL may
 *  propose, derived from the validator's tables
 *  (arbiter/policy/policy-edit-schema.ts `policyAgentEditSchema`): every op
 *  but add-model / update-model / remove-model (§4.3a). Data plane. */
export interface PolicySchemaOpRequest extends BaseRequest {
  op: "policySchema";
}

export interface PolicySchemaResult {
  edits: Record<string, unknown>;
}

export interface PolicyExplainOpRequest extends BaseRequest {
  op: "policyExplain";
  /** "agent" = the answer goes to T-LLM through the policy tools (policy-tool.ts):
   *  pending asks as a COUNT only (a page can choose their hosts), and only
   *  `sessionKey`'s own pending proposals. Default "assistant". */
  audience?: "agent" | "assistant";
  sessionKey?: string;
}

/**
 * The law as structured fields ONLY (§4.4): a configuring model may read it,
 * so nothing here is free text. Every string is a bounded TOKEN (no
 * whitespace, a path/host/URL character set, at most 200 characters); a
 * value that is not one is replaced by WITHHELD. No reason strings, no event
 * text, no symbol values, no tool results.
 */
export interface PolicyExplainResult {
  specId: string;
  lawSource: string;
  locks: Array<{ path: string; level: string; recursive: boolean; pattern: boolean; bindings: string[]; source: "policy-file" | "dashboard" }>;
  userRules: Array<{ id: string; mode: string; from: string[] | null; to: string[]; expiresAt: number | null }>;
  dispositions: Record<string, "ask" | "block">;
  origins: Record<"url" | "channel" | "dir", { trusted: string[]; untrusted: string[] }>;
  connectAllow: string[];
  relaxations: Array<{ kind: string; subject: string }>;
  pendingProposals: Array<{ id: string; requestedBy: string; createdAt: number; relaxes: Array<{ facet: string; subject: string }> }>;
  /** Empty for the agent audience. */
  pendingAsks: Array<{ destinationHost: string; count: number }>;
  pendingAskCount: number;
  ruleHits: Record<string, number>;
  /** The declared models (policy.yaml `models:`, plan 11 D2), READ-ONLY here:
   *  each field a token, `url` without its query or fragment, `tokenEnv` the
   *  variable's NAME only (never a key). policy-surface.md §8.4.4. */
  models: ModelEndpointWire[];
}

// ── Responses ─────────────────────────────────────────────────────────────

export interface OkResponse<T> {
  id: string | number;
  ok: true;
  result: T;
}

export interface ErrResponse {
  id: string | number;
  ok: false;
  error: string;
}

export type ArbiterResponse<T> = OkResponse<T> | ErrResponse;

export interface SymbolizeResult {
  /** The allocated symbol name (e.g. "$MDU:web_fetch[a1b2].text"). */
  symbol: string;
  /** The stored (post-derivation, post-escalation) confidentiality level.
   * PRESENT ONLY when the confidentiality axis is enabled — absent = axis
   * off = treat as public. Keeps the OFF wire shape byte-identical
   * (confidentiality.md §11). */
  confidentiality?: string;
}

export interface DesymbolizeResult {
  /** `text` with all known symbols replaced by their raw values. */
  text: string;
}

export interface ResolveResult {
  /** Raw value, or null if the symbol is unknown — OR if it is `no-model`
   * and this was a `deep` (quarantine) resolve, which is refused (§3.2). */
  value: string | null;
  /** The resolved symbol's confidentiality level (Plan 7). Present only on a
   * `deep` resolve with the axis ON. The caller INHERITS it onto anything it
   * derives — though it need not be trusted to: `symbolize` derives the same
   * inheritance server-side from the origin symbol, so a caller that ignores
   * this field still cannot launder the label. */
  confidentiality?: string;
  /** Bound destinations the resolved datum carries (§2). */
  bindings?: string[];
  /** Plan 11: where the endpoint named on the request runs, as the arbiter
   *  derived it (present on a `deep` resolve with the axis ON). */
  location?: "local" | "external";
}

export type ClassifyOpResult = ClassifyResult;

export interface PingResult {
  pong: true;
  protocolVersion: number;
}

/** hello — the daemon's runtime identity (runtime-instances.md). */
export interface HelloResult {
  pid: number;
  /** ISO 8601 time the server object was constructed. */
  startedAt: string;
  /** Instance id (`<utc>-<rev>-p<pid>`) when running in instance mode; null for
   * explicit-socket deployments (tests, pinned paths). */
  instanceId: string | null;
  /** Short git rev of the source the daemon loaded ("nogit" when unknown). */
  gitRev: string;
  gitDirty: boolean;
  /** The Mandu release this arbiter's code belongs to (`0.2.0-beta.6`;
   *  "unknown" when it cannot read its package.json). The launcher refuses or
   *  restarts an arbiter whose release is not its own (runtime-instances.md
   *  §4.1). Absent on an arbiter from before 2026-10-09: an older release. */
  version?: string;
  /** Which build of that release (build-identity.ts): `bundle`, the SHA-256
   *  prefix of the bundle file it runs (null from source); `rev`, the short
   *  git rev of the checkout it came from (null for an install). Two commits
   *  of one version differ here. Absent on an arbiter from before 2026-10-17. */
  build?: { bundle: string | null; rev: string | null };
  /** The socket path this server bound. */
  sockPath: string;
  /** The HUMAN-PLANE socket path (docs/design/architecture/arbiter-human-plane.md), for
   * discovery by whoever wires the human-facing consumers; null when this
   * instance serves no human channel. Absent on a pre-2026-09-30 arbiter.
   * Never a reason to ask the data socket for originals instead. */
  humanSock?: string | null;
  /** The channel this answer came on (confidentiality plan 13 §3 D9): the
   * guard and the model proxies report on `human`, where their records are
   * believed; on `data` they are claims. Absent on an arbiter from before
   * 2026-10-02, which believed the data socket. */
  channel?: "data" | "human" | "admin";
  /** Shared durable state: observability events + symbol DB. */
  eventDir: string;
  symbolDb: string;
  protocolVersion: number;
  /** Axis POSTURE this instance runs (int×conf matrix; the live-suite posture
   * guard's probe). Absent on a pre-posture arbiter — treat as unknown, not as
   * a default. */
  integrity?: boolean;
  confidentiality?: boolean;
  /** Tenant identity (policy-surface.md §2.7): "live" | "test", or
   * null for an untenanted (legacy) arbiter that accepts any tenant's events.
   * Absent on a pre-tenancy arbiter — treat as untenanted. */
  tenant?: "live" | "test" | null;
}

export interface HandlingPromptResult {
  /** The T-LLM system prompt describing the symbol contract. */
  prompt: string;
}

export interface RecordToolCallResult {
  ok: true;
}

/** Egress gate verdict — the lifted DesymbolizationDecision. */
export type DesymbolizationDecisionOpResult = DesymbolizationDecision;

/** `fsPathDecision` ⇒ the (approval-wrapped) sensitive-path gate verdict. */
export type FsPathDecisionOpResult = FsPathDecision;

/** `fileUploadDecision` ⇒ the (approval-wrapped) upload gate verdict. */
export type FileUploadDecisionOpResult = FileUploadDecision;

/** AgentShell vs HumanShell selection — the lifted ExecClassifyDecision. */
export type ClassifyExecOpResult = ExecClassifyDecision;

/** Desymbolized argv + required approvals — the lifted ResolveExecArgvResult. */
export type ResolveExecArgvOpResult = ResolveExecArgvResult;

/** allow/block + classification/evasion — the lifted ExecGateResult. */
export type ExecGateOpResult = ExecGateResult;

/** `execDecisionFor` ⇒ the proxy's recorded exec decision, or null on a miss. */
export interface ExecDecisionForOpResult {
  decision: RecordedExecDecision | null;
  /** The signature the lookup keyed on (observability / debugging). */
  signature: string;
}

/** `reportExecCleanVerdict` ⇒ what the report RESOLVED to post-gates (the
 * caller sees which gate failed, or the standing unclean a duplicate hit). */
export interface ReportExecCleanVerdictOpResult {
  verdict: ExecCleanVerdict;
}

/** `execCleanVerdictFor` ⇒ the resolved verdict, or null on a miss. */
export interface ExecCleanVerdictForOpResult {
  verdict: ExecCleanVerdict | null;
}

/** `reportExecTwins` ⇒ how many candidates the store kept (0 = nothing to hint). */
export interface ReportExecTwinsOpResult {
  recorded: number;
}

/** `whyPath` ⇒ the file as the law sees it. */
export interface WhyPathOpResult {
  path: string;
  /** False when the confidentiality axis is OFF: nothing is masked. */
  axis: boolean;
  level: string;
  /** What decided (see {@link PathLevelOpResult.rule}); null = public by default. */
  rule: string | null;
  bindings: string[];
  /** Plan 13 §5.2: as {@link PathLevelsEntry.values} / `fileBindings`. */
  values?: Array<{ key: string; bindings: string[] }>;
  fileBindings?: string[];
  /** Stricter pattern labels a human label outranked (the tester's hint). */
  outranked: Array<{ path: string; level: string }>;
  /** The file's reader list from the law (`paths[].readers`), as written. */
  readers: unknown[];
  /** Plan 13 §8 decision (b): per `readers` entry, same order, true when it
   *  admits nothing (a shell or an interpreter with no `script:` pin, or,
   *  since 2026-10-03, a printer in any form, `entryAdmitsNothing`). Absent
   *  from an older arbiter. */
  readersAdmitNothing?: boolean[];
  /** Plan 13 D8, printers admit nothing (2026-10-03): per `readers` entry,
   *  same order, true when it names a printer (`readerPrints`, by name or
   *  pinned path, or, since the !437 leftover (2), a pinned hash that is a
   *  host printer's: `binaryPrints`), so `mandu why` says why it admits nothing. Absent from
   *  an older arbiter. */
  readersPrint?: boolean[];
  /** Plan 13 D8 and §8 decision (b) by content (2026-10-03): per `readers`
   *  entry, same order, the installed program a pin's hash is byte for byte
   *  when its name and path do not say so (`renamedCopyOf`: `{ app: mytool,
   *  sha256: <python3's> }` → `python3.12`), else null, so `mandu why` says
   *  what the copy is. Absent from an older arbiter. */
  readersCopyOf?: Array<string | null>;
  /** Plan 13 D8 (12), the allow-list (2026-10-04): per `readers` entry, same
   *  order, true when its program reads the twin: it is neither a vetted
   *  reader nor vouched for (`prints: nothing`), `entryReadsTwin`. Absent
   *  from an older arbiter. */
  readersReadTwin?: boolean[];
  /** What a program not on the list gets (`paths[].others`), or null (the default). */
  others: string | null;
  /** The consumer table's default readers for this file (§11.3) and whether
   *  the wire release could serve them instead (confidentiality-plan-13-reader-set-labels.md §10). */
  consumers: string[];
  /** Plan 13 D8 and §4.9 (2026-10-04): per `consumers` entry, same order,
   *  true when it is a printer (`readerPrints`: `curl` for `.netrc`, `scp`
   *  for the ssh keys, `git` and `git-credential-store` for
   *  `.git-credentials`), which is no default reader: it gets the twin (the
   *  wire release's when served). Absent from an older arbiter. */
  consumersPrint?: boolean[];
  wire: { served: boolean; why: string } | null;
  /** The shape the file's PATH suggests (a structured twin keeps keys raw;
   *  null = a whole-file placeholder). Kept for older clients: what the twin
   *  really is depends on the file's text, and `twin` says it. */
  twinShape: string | null;
  /** 2026-10-09: the twin a registration makes of the file as it is now
   *  (registry.ts `twinFormOf`): `structured` with `fields` masked values,
   *  `own-text`, or `whole-file` (`shape`: the shape that found no secret
   *  value, or null). Present with the axis on, a level above `public` and a
   *  readable, non-empty file; absent from an older arbiter. */
  twin?: { form: "structured" | "own-text" | "whole-file"; shape: string | null; fields: number };
  /** Plan 10 §11.13.3: the commands an `~/.ssh/config` twin withholds
   *  (`ProxyCommand` off the relay grammar, `LocalCommand`,
   *  `RemoteCommand`, `KnownHostsCommand`, `Match exec`), by 1-based line
   *  and keyword; never their text. Present only for an ssh config with the
   *  axis on; absent from an older arbiter. */
  withheld?: Array<{ line: number; keyword: string }>;
  /** Prior human verdicts on programs opening (`kind: "open"`) or changing
   *  (`kind: "write"`, write-protection.md §2.1) this file (the Inbox).
   *  `exe`: the executable the verdict is for (Plan 13 D8 and its follow-up:
   *  a verdict names one binary by path and hash; the hash is not carried);
   *  absent on a row written before 2026-10-02. `kind` absent = `open` (an
   *  arbiter before the follow-up). Plan 13 §8 decision (c): `script`, the
   *  script an interpreter's verdict names; `run`, a verdict about one run
   *  of an interpreter running no pinned script (a held change only);
   *  `stale`, a verdict naming an interpreter alone (written before the
   *  decision), which applies to nothing. Plan 13 D8, printers admit
   *  nothing (2026-10-03): `printer`, an `open` verdict about a program that
   *  prints or copies a file (`printerOpenVerdict`), which applies to
   *  nothing and is never asked again. Plan 13 D8 (12): `kind: "trust"`, the
   *  warning question about an unvetted program; `unvetted`, an `open` answer
   *  about one, which no longer counts. */
  verdicts: Array<{ kind?: "open" | "write" | "trust"; app: string; exe?: string; status: string; scope: string; script?: string; run?: boolean; stale?: boolean; printer?: boolean; unvetted?: boolean }>;
  /** First-session tour item 17: the changes waiting in Approvals that
   *  would change this answer (a held policy.yaml edit, a proposal, a
   *  suggestion), each with the level, bindings and rule it would make.
   *  The rows above are the law in force until the human answers. Never a
   *  value. Absent from an older arbiter. */
  pending?: WhyPendingChange[];
  /** The file is an AI agent's own (secret-discovery.ts `agentFileOf`,
   *  secret-discovery.md §1.10): one of its login files (left raw by a
   *  launch that runs that agent, a placeholder copy in every other) or its
   *  own data (left raw in every launch; only a command that names the path
   *  is masked for the AI). Absent: neither, or an older arbiter. */
  agentFile?: { kind: "login" | "store"; agent: string };
  /** Plan 10 §11.13 (2026-10-17): the launch whose HOME the answer judged
   *  the path under as well as the caller's `home` (the stricter deciding,
   *  as the guard judges that session's opens; the twin as the guard serves
   *  it, `twinMatchOf`): the launch of the request's `session`, else the
   *  newest live launch (`newest`). `home: null`: the named session has no
   *  live launch on this arbiter, so no launch HOME applied. Human plane
   *  only (a data-socket request names no session's HOME); absent with no
   *  live launch, the axis off, or an older arbiter. */
  launch?: { session: string; home: string | null; newest: boolean };
}

/** One change waiting in Approvals that would change a `why` answer. `from`:
 *  `file` (policy.yaml changed on disk), `agent` (an agent asked), `scan`
 *  (Mandu's scan suggests it), `other` (the dashboard). */
export interface WhyPendingChange {
  id: string;
  from: "file" | "agent" | "scan" | "other";
  /** For a path: what the change would make it; for a host: absent. */
  level?: string;
  bindings?: string[];
  rule?: string | null;
}

/** `whyHost` ⇒ the destination as the law sees it. */
export interface WhyHostOpResult {
  host: string;
  axis: boolean;
  /** Registered secrets and labeled paths whose bindings admit this host. */
  bound: Array<{ path: string; level: string; binding: string[]; source: "label" | "registry" }>;
  /** The egress gate's answer for a secret bound to this host and for one
   *  that is not (a probe: nothing queued, nothing counted). */
  release: { bound: { decision: DesymbolizationDecision; stage: string } | null; unbound: { decision: DesymbolizationDecision; stage: string } | null };
  /** The law's `destinations:` rows for this host. */
  destinations: Array<{ host: string; port: number | "*"; proto: string; connect: string; reason?: string }>;
  /** Prior human verdicts for sends to this host. */
  verdicts: Array<{ symbol: string; status: string; scope: string }>;
  /** Tour item 17: the changes waiting in Approvals that would change which
   *  secrets may go here or the law's rows for this host. Absent from an
   *  older arbiter. */
  pending?: WhyPendingChange[];
  /** confidentiality.md §2.3: when this host is an issuer's API host, the
   *  issuer, the key formats it receives without asking, and whether the
   *  law in force has that on (`issuer_bindings`). Absent: not an issuer
   *  host, or an older arbiter. */
  issuer?: { id: string; name: string; shapes: string[]; on: boolean };
}

/** `pathLevel` ⇒ the level a read of `path` would mint with today. */
export interface PathLevelOpResult {
  level: string;
  bindings: string[];
  /** False when the confidentiality axis is OFF (level is always public). */
  axis: boolean;
  /** WHAT decided, for a human reader (the watch panel's per-file label chip):
   *  `label:<path>` a human label (policy.yaml `paths:` or a dashboard act; the
   *  path is the deciding row, possibly an ancestor), `derived:<path>` a file a
   *  HIGH session wrote, `prefix:…` / `shape:…` the default-secret catalog,
   *  null = nothing matched (public by default). Observability only: no caller
   *  may decide on it. */
  rule: string | null;
}

/** One path of a `pathLevels` answer. */
export interface PathLevelsEntry {
  /** The path as asked. */
  path: string;
  level: string;
  bindings: string[];
  /** As {@link PathLevelOpResult.rule}. */
  rule: string | null;
  /** Where the deciding HUMAN label is kept, when one decided: `policy` a
   *  policy.yaml `paths:` entry, `page` a label made on the dashboard before
   *  labels moved to policy.yaml (the mandu.db store; it wins over policy.yaml
   *  on the same path), `models` a model's client key (plan 12 D3). null when
   *  no human label decided (the catalog, a derived label, or nothing). */
  store: "policy" | "page" | "models" | null;
  /** Plan 13 §5.2: the deciding human label's per-value bindings
   *  (`values:`, in document order) and its own declared `bindings`
   *  (what a value with no entry takes; `bindings` above is then the whole
   *  file's, the intersection). Absent when the label has none. */
  values?: Array<{ key: string; bindings: string[] }>;
  fileBindings?: string[];
}

/** `pathLevels` ⇒ one entry per asked path, in order. */
export interface PathLevelsOpResult {
  /** False when the confidentiality axis is OFF: the levels are what the
   *  labels would do, and nothing enforces them now. */
  axis: boolean;
  levels: PathLevelsEntry[];
}

/** `execTwinsFor` ⇒ the candidate twins for the command (unique by `abs`, at
 * most 8) plus the signature the lookup keyed on (observability). */
export interface ExecTwinsForOpResult {
  signature: string;
  twins: ExecTwinCandidate[];
  /** Named files beyond `twins` (a count; the note says "N more not listed"). */
  more: number;
}

/** `escalateExec` ⇒ the escalation verdict. */
export interface EscalateExecOpResult {
  /** Which shell the command may run in AFTER the escalation gate. */
  shell: ExecShell;
  /** True iff a human approved the escalation (→ HumanShell). */
  approved: boolean;
  /** True iff the escalation is now PENDING a human decision (queued). */
  requiresApproval: boolean;
  reason: string;
  /** Decision provenance (policy-surface.md §9.3) — the server has always
   * stamped this on the wire; declared here so the contract matches. */
  ruleRef?: RuleRef;
  /** The approval-queue entry a fresh/pending escalation created or bumped
   * (`egr-<n>`) — the event-side join back to the Pending tab (§5). */
  approvalId?: string;
}

/** `policySnapshot` ⇒ the trust-rule table (the pure PolicyRuleSnapshot) PLUS
 * the server-composed standing state the Policy panel renders
 * (policy-surface.md §9.4): axis posture, the usage-gate rule catalog, and
 * the approval queue at EVERY status — the standing human verdicts that were
 * invisible while only the pending list had a UI. Additive: old consumers read
 * the trust fields and ignore the rest. Composed in the server handler because
 * posture + verdicts are SERVER state, not part of the pure policy mirror. */
export type PolicySnapshotOpResult = PolicyRuleSnapshot & {
  posture: { integrity: boolean; confidentiality: boolean };
  /** `gates` (policy-surface.md §9.8): the gate catalog the panel's per-row
   * detail cites (title / definedIn / doc / evaluation) — shipped from the
   * enforcing code like `rules`, so it cannot drift. Optional so an older
   * result parses; a consumer must OMIT the citation lines when absent, never
   * invent them. */
  usage: { rules: UsageRule[]; sensitivePaths: string[]; gates?: UsageGate[] };
  verdicts: EgressApproval[];
  /** SIEM-lockdown egress posture (siem-integration.md §4.3, scenario D).
   *  Optional — a pre-scenario-D arbiter omits it (treat absent as "normal"). */
  egressPosture?: "normal" | "lockdown";
  /** Where the active policy came from (built-ins / YAML file / injected
   * engine) — policy-surface.md §9.8 "law source". Optional (older arbiters
   * omit it; render as unknown, never guessed). */
  lawSource?: PolicyLawSource;
  /** The operator's law from policy.yaml (policy-surface.md §2.1,
   * stage 4): lists, locked-file labels, dispositions, user rules — plus the
   * relaxations the compiled law introduces and per-rule hit counts. */
  document?: {
    lists: Record<string, string[]>;
    /** `readers` and the per-entry judgment (Plan 13 D8 (13), P0 item 14):
     *  present for a path with a reader list; the arrays follow `readers`
     *  entry for entry, as `whyPath`'s do. Absent on an older arbiter. */
    paths: {
      path: string; level: string; bindings: string[]; recursive: boolean; glob?: boolean;
      readers?: Array<string | { app: string; path?: string; sha256?: string; from?: string; output?: "secret" | "clear" | "mask"; mask?: string[]; script?: string; scriptSha256?: string; prints?: "nothing" }>;
      readersAdmitNothing?: boolean[];
      readersReadTwin?: boolean[];
      readersCopyOf?: Array<string | null>;
      others?: "deny" | "twin";
      /** Plan 13 §5.2: per-value bindings (`values:`), in document order.
       *  `bindings` stays the file's own as written. */
      values?: Array<{ key: string; bindings: string[] }>;
      /** With `values`: where the WHOLE file may go (the intersection of
       *  `bindings` and every value's, value-bindings.ts). */
      wholeBindings?: string[];
    }[];
    rules: Record<string, { mode: string }>;
    userRules: {
      id: string; kind: string; from: string[] | null; to: string[]; mode: string;
      reason?: string; by?: string; added?: string; expires?: string | null;
    }[];
    /** Reachability rules (policy-surface.md §2.3, stage 4b), lists expanded. */
    destinations: { host: string; port: number | "*"; proto: "tcp" | "udp"; connect: "allow" | "deny"; reason?: string }[];
    /** Plan 11 D6: declared model endpoints (policy.yaml `models:`), read-only.
     *  Optional: an older arbiter omits it. */
    models?: ModelEndpointWire[];
    /** The version of each declared model's entry in the user's file, by
     *  name (`itemVersionOf`; null-valued for an administrator's entry the
     *  file does not name): Settings › Models' update sends it back
     *  (`policyPropose.basedOn`) and is refused as stale once the entry
     *  changed. Absent from an older arbiter. */
    modelVersions?: Record<string, string>;
    /** The version of each file rule's entry in the user's file, by `paths[].path`
     *  as listed (`itemVersionOf`; an entry the file does not name has the
     *  absent version): the Rules page's label buttons send it back with
     *  the change (`policyPropose.basedOn`). Absent from an older arbiter. */
    pathVersions?: Record<string, string>;
    /** Plan 12 D4: the perimeter in force and who set its networks. */
    perimeter?: { networks: string[] | null; domains: string[]; by: "administrator" | "you" | "narrowed" };
    /** Plan 12 D5: the administrator's layer, when one is in force (or a
     *  re-read of it was refused). */
    modelsAdmin?: { files: string[]; locked: boolean; conflicts: string[]; refused: string[]; removed: Array<{ name: string; file: string }> };
  };
  relaxations?: { kind: string; subject: string; detail: string }[];
  hits?: Record<string, { hits: number; auditHits: number; lastHit: number | null }>;
  /** The policy FILE's status (stage 5a): where it is, whether the last load
   * or apply validated, the problems if not, when the law in force was loaded.
   * `valid:false` = the file on disk is refused and the last-known-good law is
   * in force — the panel shows a banner. */
  policyFile?: PolicyFileStatusWire;
};

/** `egressApprovals` ⇒ the queued entries (newest-resolved first by lastSeen). */
export interface EgressApprovalsResult {
  approvals: EgressApproval[];
}

/** `resolveEgressApproval` ⇒ the entry after the human verdict was applied. */
export interface ResolveEgressApprovalResult {
  approval: EgressApproval;
}

/** `forgetEgressApproval` ⇒ the entry as it was before it was forgotten. */
export interface ForgetEgressApprovalResult {
  approval: EgressApproval;
}

/** `setSessionPosture` ⇒ the posture after the request (tighten-only unless
 * `allowRelax`). `applied` is false when the guard refused (an un-flagged loosen
 * or a same-level no-op); `posture` is the CURRENT global posture either way. */
export interface SetSessionPostureResult {
  posture: "normal" | "lockdown";
  applied: boolean;
  from: "normal" | "lockdown";
  to: "normal" | "lockdown";
  reason: string;
}

/** `setSessionSpec` ⇒ what was actually bound. `applied` is false when the
 * requested spec id was unknown — the session is then bound to "fail-closed"
 * (every tool UNTRUSTED), never left on another agent's spec. */
export interface SetSessionSpecResult {
  /** The spec id the session is now bound to. */
  bound: string;
  /** true ⇔ `bound` is the spec the caller asked for. */
  applied: boolean;
  reason: string;
}

/** `symbolShape` ⇒ the resolved value's line count ONLY (no length, widths or
 * label — reply-row-reservation.md §5.2), or null (the wire result) when the
 * token is not exactly one known symbol. `rows` is present exactly when the
 * request carried a `width` (§11.5): the value's screen-row count there. */
export interface SymbolShapeResult {
  lines: number;
  rows?: number;
  /** With a layout: the display width of the value's last row (§14). */
  last?: number;
}

/** `setSessionRelay` ⇒ acknowledged. */
export interface SetSessionRelayResult {
  ok: true;
}

/** `sessionRelay` ⇒ the session's last reported relay state (the wire result
 * is this or null). `updatedAt` is the arbiter's receive time, epoch ms. */
export interface SessionRelayWire {
  mode: SessionRelayMode;
  reserve: boolean;
  cols?: number;
  rows?: number;
  /** The filter paints v2 heads (§11.5); absent from a v1 filter's report. */
  wrap?: boolean;
  /** The TUI's wrap rule (§17); absent: `ink`. */
  rule?: ReplyLayoutRule;
  updatedAt: number;
}

/** `emit` ⇒ the arbiter-assigned per-session monotonic seq for the stored event. */
export interface EmitResult {
  seq: number;
}

/** `events` ⇒ persisted events with seq > sinceSeq, in seq order. */
export interface EventsResult {
  events: StoredEvent[];
}

/** `sessions` ⇒ one summary row per known session. */
export interface SessionsResult {
  sessions: SessionSummary[];
}

/** `deleteSession` ⇒ acknowledged: the log file, per-session in-memory state and
 * live subscriptions are gone. */
export interface DeleteSessionResult {
  ok: true;
}

/** A single `subscribe` stream frame: a backlog or live-pushed event. Each frame
 * is a normal NDJSON OkResponse whose result carries `type:"event"`. */
export interface SubscribeEventFrame {
  type: "event";
  event: StoredEvent;
}
