/**
 * arbiter-client — the arbiter dependency the OpenAI (Responses-API) proxy speaks to.
 *
 * Mandu Track A (interceptors/openai-proxy). Mirrors
 * interceptors/anthropic-proxy/src/arbiter-client.ts: the proxy never opens the
 * symbol-table DB directly — the arbiter (arbiter/) owns the symbol table + policy
 * engine, and we call it over its Unix-socket NDJSON IPC. This module defines the
 * NARROW interface the proxy needs (`Arbiter`) plus a thin adapter
 * (`ArbiterClientAdapter`) that fulfils it via the real arbiter IPC client
 * (arbiter/ipc/client.ts).
 *
 * This proxy is SIMPLER than the anthropic-proxy: symbolization is request-side only
 * (the SSE response is never symbolized or recorded; with a view map it is only
 * path-rewritten in flight, src/sse-rewrite.ts), so the narrow surface is the
 * three security-critical request-side ops (plus best-effort `emit`, off the
 * security path):
 *   - classify({tool, field?, value, boundary, origin?, params?}) → {trust,...}
 *   - symbolize({tool, value, field?, origin?, sessionKey?, callId?})  → symbol
 *   - handlingPrompt({mode?})                                          → {prompt}
 * plus reply row reservation's two utility-only ops, `symbolShape` and
 * `sessionRelay`, forwarded ONLY to a second client on the arbiter's human
 * plane (reply-row-reservation.md §11.7; the adapter's constructor).
 *
 * Decoupling rationale: the proxy is written against `Arbiter`, not the concrete
 * client. Tests inject a MockArbiter (test/helpers/mock-arbiter.ts) so the suite
 * never depends on the arbiter daemon. At integration time the adapter wires the
 * real client.
 *
 * The op shapes mirror arbiter/ipc/protocol.ts and arbiter/policy/policy-
 * interface.ts exactly.
 */

/**
 * The `$MDU:*` symbol pattern, mirrored locally from arbiter/symbol-table/
 * symbol-format.ts `MDU_SYM_FORMAT.pattern`. The proxy is dependency-free of the
 * arbiter package, so we keep this in sync here rather than import it. Used by the
 * §9 oracle predicate / tests to detect symbol tokens.
 *
 * Returns a FRESH RegExp each call (the global flag carries mutable lastIndex
 * state; callers should not share one instance).
 */
export function getSymbolPattern(): RegExp {
  return /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*|\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;
}

/** Mirrors arbiter/policy/policy-interface.ts `Trust`. */
export type Trust = "TRUSTED" | "UNTRUSTED";

/** Mirrors arbiter/policy/policy-interface.ts `Boundary`. */
export type Boundary = "model_context" | "network" | "filesystem" | "shell";

/** Mirrors arbiter/policy/policy-interface.ts `ClassifyRequest`. */
/** `forwardedClear`'s answer with `since` (arbiter/ipc/protocol.ts
 *  ForwardedClearResult): the known subset, the store's generation, and the
 *  ids recorded after `since` ("Two launches at once", confidentiality.md
 *  §7.1). */
export interface ForwardedClearAnswer {
  ids: string[];
  generation?: number;
  recent?: string[];
  recentComplete?: boolean;
}

export interface ClassifyRequest {
  tool: string;
  field?: string;
  value: string;
  boundary: Boundary;
  origin?: string;
  /** The SAME origin, spelled in the arbiter's world — HumanView (Plan 9). Under
   *  a view map the agent's spelling is the AgentView twin, while every path
   *  policy the arbiter owns is keyed in HumanView. Consumed ONLY by the
   *  confidentiality derivation — TRUST never sees it, so a spelling translation
   *  can never move a datum UNTRUSTED → TRUSTED. */
  originHuman?: string;
  params?: Record<string, unknown>;
  /** `params` spelled in HumanView (every string leaf through the view map);
   *  present only when the map changed one. Confidentiality-only, like
   *  `originHuman`: a tool the session's spec does not map has every string
   *  of its input read for labeled paths (plan 10 §11.11). */
  paramsHuman?: Record<string, unknown>;
  /** The session's directory, for a shell call whose params name no
   *  `workdir` (`codexSessionCwd`, HumanView). Confidentiality-only. */
  workdirDefault?: string;
  /** clean-tree-release.md R3: the call whose recorded process tree the
   *  arbiter's clean-tree release reads (this proxy's classify names no
   *  `callId`, whose start-directory reading it does not take). */
  treeCallId?: string;
  /** Session identity for SESSION-KEYED spec resolution (agent-e2e-harness.md
   *  §7.1): the same key `symbolize` carries. A session bound via the
   *  arbiter's `setSessionSpec` op classifies against that agent's inbound
   *  spec; absent/unbound falls back to the arbiter's process-global spec. */
  sessionKey?: string;
}

/** Mirrors arbiter/policy/policy-interface.ts `ClassifyResult`. */
export interface ClassifyResult {
  trust: Trust;
  category: string | null;
  reason: string;
  /** Confidentiality level of the classified datum (confidentiality.md §2).
   * ABSENT while the arbiter's confidentiality axis is OFF — treat absent as
   * "public". Any present non-"public" value (known or not) means the datum
   * is secret-labeled and must be symbolized even when integrity-TRUSTED. */
  confidentiality?: string;
  /** The tokens of the call's own input that name a secret path, as written
   *  there (arbiter `labelForClassify`'s `paths`): what the path-derived
   *  note names, once found verbatim in the model's own command. */
  namedPaths?: string[];
  /** Beside `namedPaths` (arbiter named-twins.ts, confidentiality.md §7.1):
   *  for a named token whose secret files all have a twin of one kind, that
   *  kind, so the path-derived note can say how to read the file itself
   *  (`pathDerivedTwins`). Explains only. */
  namedTwins?: Array<{ path: string; twin: string }>;
  /** `value-backstop`: the level is the arbiter's value backstop raise of a
   *  verdict its policy called public (plan 15 §4.1). The proxy echoes it as
   *  `secretBy` on the symbolize only when it raised the level no further. */
  raisedBy?: "value-backstop";
  /** backstop-value-only.md: the arbiter's value-only release, offered
   *  beside a `value-backstop` raise (taken only through
   *  `acceptValueOnlyOffer`, and only when the call's evidence is clean). */
  valueOnly?: { text: string; spans: Array<{ start: number; end: number; symbol: string }> };
  /** clean-tree-release.md: the arbiter's clean-tree release, offered
   *  beside a path-derived verdict of a shell command: `spans` may be empty
   *  (`text` is then the value as it is). Taken only through
   *  `acceptPathReleaseOffer`, and only when the call's evidence is clean;
   *  else the result is masked whole. */
  pathRelease?: { text: string; spans: Array<{ start: number; end: number; symbol: string }>; listing?: { operands: string[]; part: "first" | "last" } };
}

/** Mirrors arbiter/ipc/protocol.ts `SymbolizeRequest` (minus id/op). */
export interface SymbolizeArgs {
  tool: string;
  value: string;
  field?: string;
  origin?: string;
  /** The origin in the arbiter's world (HumanView) — see ClassifyRequest. */
  originHuman?: string;
  sessionKey?: string;
  callId?: string;
  /** Confidentiality level to store (the arbiter re-derives and takes max). */
  confidentiality?: string;
  /** Integrity half of the label; only "trusted" counts server-side. */
  integrity?: string;
  /** `"codex"`: the value is Codex's WHOLE function_call_output, led by the
   *  head its runtime writes; `"codex-mcp"`: a known MCP call's whole output,
   *  led by Codex's MCP head. The arbiter, matching that kind's head by its
   *  own grammar at offset 0, does not fingerprint the head's lines as lines
   *  of the registered value (plan 10 §11.14). `"write-notice"`: an agent's
   *  `write` tool's whole output, led by its fixed success notice for the
   *  call's own path (plan 15 §13.10). */
  resultHead?: "codex" | "codex-mcp" | "write-notice";
  /** `"value-backstop"`: the level is the classify verdict's `raisedBy` backstop
   *  raise and this proxy raised it no further (SymbolizeRequest.secretBy,
   *  plan 15 §4.1). `"path-rule"`: the level is the classify verdict's own
   *  path-derived level (the command names a secret path), with no
   *  backstop raise, and this proxy raised it no further (plan 15 §13.12).
   *  The arbiter checks its own records before it acts on either. */
  secretBy?: "value-backstop" | "path-rule";
}

/**
 * Tool-battery capability FACTS for the handlingPrompt op, mirrored from
 * arbiter/ipc/protocol.ts `HandlingPromptRequest.capabilities`. The proxy
 * reports what the request's `tools` array contains; the arbiter maps the
 * facts to prompt sections. Every ABSENT field defaults to present on the
 * arbiter side, so reporting nothing yields the full prompt.
 */
export interface HandlingPromptCapabilities {
  /** An inspect_symbol tool is in the battery. */
  inspect?: boolean;
  /** policy_list / policy_add / policy_del are in the battery. */
  policyTools?: boolean;
  /** The mandu-policy MCP tools are in the battery (policy-surface.md §8.5.1). ABSENT = false. */
  manduPolicy?: boolean;
  /** A shell/exec tool is in the battery. */
  exec?: boolean;
  /** The session's secret posture (src/secret-posture.ts; env
   * MANDU_SECRET_POSTURE, set by the launcher). `read-blocked` (macOS) adds
   * the "blocked credential files" section with the confidentiality axis ON.
   * Not a tool fact; reported only when set (docs/design/agents/handling-prompt.md §2). */
  secretPosture?: string;
}

/** Request for the handlingPrompt op. */
export interface HandlingPromptArgs {
  /** Optional handling-prompt mode (e.g. full/dual-only). Arbiter-defined. */
  mode?: string;
  /** Tool-battery capability facts (see HandlingPromptCapabilities). */
  capabilities?: HandlingPromptCapabilities;
  /** The session the prompt is for (plan 11 phase 3, §7.2): the arbiter reads
   *  its main-model binding. Absent = the strict (outside model) text. */
  sessionKey?: string;
}

/**
 * An observability event handed to the arbiter's privileged event log. The proxy
 * treats it as an opaque record (the canonical `ManduEvent` shape lives in
 * src/events.ts) — arbiter-client only needs the emit op's request/response
 * contract. Kept as `unknown` here so this module stays decoupled from the event
 * builder; the proxy/tests pass a fully-formed `ManduEvent`.
 */
export type ArbiterEvent = unknown;

/**
 * Reply to an `emit`: the arbiter stamps a monotonic per-session sequence number.
 * The proxy IGNORES this (emission is fire-and-forget / off the security path);
 * it exists only so the contract round-trips and the mock can assert ordering.
 */
export interface EmitResult {
  seq: number;
}

/** Mirrors arbiter/policy/exec-gate.ts `ExecGateRequest`. */
export interface ExecGateRequest {
  /** The session the command belongs to. LOAD-BEARING since Plan 8 — the arbiter
   *  tightens exec in a HIGH session (one that has read secret content into
   *  context) and cannot tell which session this is without it. */
  sessionKey?: string;
  /** The raw shell command as the model wrote it (symbols still opaque). */
  command: string;
  /** Working directory the command would run in. */
  cwd?: string;
  /** The function_call's call_id (plan 13 D9 follow-up): on the human socket
   *  the arbiter records the call's gate time and this command for it, which
   *  bounds and binds the call to the agent's shell for it. */
  callId?: string;
}

/** Mirrors arbiter/policy/exec-gate.ts `ExecGateEvasion`. */
export interface ExecGateEvasion {
  kind: "absolute_path_net_tool" | "env_prefix_override";
  evidence: string;
}

/** Mirrors arbiter/policy/exec-gate.ts `ExecGateResult`. `block` means an
 * untrusted symbol sits in a command/execution position. */
export interface ExecGateDecision {
  decision: "allow" | "block";
  reason: string;
  symbols: string[];
  evasion: ExecGateEvasion[];
  shell: "AgentShell" | "HumanShell";
  identifier: string | null;
  /** ALLOW only: the command with each secret placeholder the agent's shell
   * would expand requoted, so the program receives it whole (arbiter
   * shell-placeholder-quoting.ts; confidentiality.md §7). Delivered in place
   * of a shell call's command (exec-gate.ts). Mirrors the anthropic-proxy. */
  requoted?: string;
}

/**
 * The narrow arbiter surface the OpenAI proxy depends on. Anything that satisfies
 * this — the real adapter or a mock — can drive the proxy.
 */
/** Who wrote a segment of user-role text (confidentiality-plan-15 §3.1). */
export type PromptSegmentOrigin = "human" | "harness" | "side-call";

/** The `filterPrompt` request (plan 15 §3.2). Never a dry run from a proxy:
 *  that is the dashboard's, on the human plane. Mirrors
 *  anthropic-proxy/src/arbiter-client.ts. */
export interface FilterPromptRequest {
  session?: string;
  agent: string;
  segments: Array<{ id: string; origin: PromptSegmentOrigin; text: string }>;
  /** Phase 3 (§7): this proxy waits on a `hold` and asks again. */
  holds?: boolean;
  /** Phase 3: the last ask of a held request, its deadline passed (ms held). */
  heldMs?: number;
}

/** Where an `ask` finding's hold stands (arbiter prompt-filter/holds.ts). */
export interface PromptHoldStateWire {
  state: "pending" | "sent" | "masked" | "cancelled" | "timed-out" | "default";
  approvalId?: string;
  why?: string;
}

/** One finding as the arbiter reports it. */
export interface PromptFindingWire {
  start: number;
  end: number;
  category: string;
  filterId: string;
  action: "pass" | "log" | "redact" | "mask" | "ask" | "block";
  symbol?: string;
  how?: "value" | "line" | "merged";
  /** Phase 3: the span's opaque reference (a "let it through" names it). */
  ref?: string;
  /** Phase 3: a human verdict let this span through as written. */
  let?: "once" | "session";
  /** Phase 3: an `ask` finding's hold. */
  hold?: PromptHoldStateWire;
  /** Next to `ref`: a locked administrator's `ask` row covers the category
   *  (plan 15 §12, 2026-10-04), computed by the arbiter: a verdict covers
   *  this message only. Copied into the event, never decided here. */
  onceOnly?: true;
}

/** The arbiter's answer (arbiter/ipc/protocol.ts FilterPromptResultWire). */
export interface FilterPromptResult {
  segments: Array<{
    id: string;
    origin: PromptSegmentOrigin;
    action: "pass" | "rewrite" | "hold" | "block";
    text?: string;
    reason?: string;
    /** `hold` (phase 3): the Inbox row and the time left before the default. */
    hold?: { approvalId: string; timeoutMs: number };
    /** Phase 3: the message's opaque reference. On an answer with no
     *  finding to reference, the arbiter's word that the message had one
     *  before in the session (its note clears; plan 15 §13.7 item 10). */
    turn?: string;
    findings: PromptFindingWire[];
    skipped: number;
    cached: boolean;
  }>;
  enforcing: boolean;
  dryRun: boolean;
  digest: { policy: string; packs: string; values: string };
}

/** Mirrors arbiter/policy/rule-ref.ts `RuleRef` — decision provenance
 *  (policy-surface.md §9.3), as the anthropic-proxy's arbiter-client.ts. */
export interface RuleRef {
  source: "rule" | "verdict" | "fail-closed";
  id: string;
}

/** Mirrors arbiter/policy/file-upload.ts `FileUploadDecisionRequest` (the
 *  anthropic-proxy's copy, field for field): may `tool` send the bytes of
 *  the absolute HumanView `path` off the machine? This proxy asks only the
 *  UNMAPPED form (unmapped-upload.ts: a local path in the input of a tool
 *  Codex does not map), with no host. */
export interface FileUploadDecisionRequest {
  tool: string;
  path: string;
  /** "" when the host is not known (the unmapped form). */
  destination: string;
  /** More hosts the bytes may reach: a binding must name each. */
  destinations?: readonly string[];
  /** The unmapped form: the arbiter reads the session's mapping first. */
  unmapped?: boolean;
  /** The approval row's session (and, in the unmapped form, whose mapping
   *  and guard the arbiter reads). */
  sessionKey?: string;
}

/** Mirrors arbiter/policy/file-upload.ts `FileUploadDecision` (the
 *  sensitive-path gate's verdict shape). */
export type FileUploadDecision =
  | { allow: true; reason: string; ruleRef?: RuleRef }
  | { allow: false; requiresApproval: boolean; reason: string; ruleRef?: RuleRef; approvalId?: string };

export interface Arbiter {
  /** Agent-sign-in.md §3.9: the agent's own key for an auth header
   *  (auth-substitution.ts). Optional: a mock without it keeps every
   *  placeholder. */
  authCredential?(req: { symbol: string; destination: string; scheme: "http" | "https"; sessionKey?: string }): Promise<{ value: string | null; reason: string }>;
  classify(req: ClassifyRequest): Promise<ClassifyResult>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  /** Fetch the handling system prompt to inject so T-LLM treats symbols as
   * opaque. */
  handlingPrompt(args?: HandlingPromptArgs): Promise<{ prompt: string }>;
  /** Model-context exec gate (exec-routing.md §3): classify a Codex shell
   * command and decide allow/block (blocks only an untrusted symbol in
   * command/execution position). A THROW is treated as unreachable → fail
   * closed (block sentinel), never open. */
  execGate(req: ExecGateRequest): Promise<ExecGateDecision>;
  /** Plan 10 §4.2: the confidentiality taint of the process tree behind a
   *  tool call (matched by callId, else by the command's exec signature), and
   *  the output rule the fold chose. Optional: an arbiter predating plan 10
   *  has no taint to report. A THROW is treated as "tainted, rule secret"
   *  (fail-closed) by the caller. Mirrors anthropic-proxy/src/arbiter-client.ts. */
  callTaint?(req: { callId: string; command?: string; sessionKey?: string; output?: string; codexHead?: boolean; unmappedTool?: string; builtin?: boolean }): Promise<CallTaintWire>;
  /** Plan 13 D9 follow-up: the command the proxy DELIVERED to the agent for a
   *  call (after the exec gate and the view map), recorded before the call is
   *  relayed; `callTaint` binds the call by it, never by the arguments Codex
   *  echoes back. Optional: without it the call binds by execGate's record
   *  alone (fail-closed on a miss). Mirrors the anthropic-proxy. */
  recordCallCommand?(req: { callId: string; command: string; sessionKey?: string }): Promise<{ recorded: boolean }>;
  /** Plan 10 §11.13: the taint of the stdio MCP server behind `tool`, mapped
   *  by the argv the launcher registered and the guard recorded. Optional: an
   *  arbiter without it maps nothing (every server unmapped). A THROW is
   *  treated as tainted (fail-closed) by the caller. */
  mcpServerTaint?(req: { tool: string; sessionKey?: string }): Promise<McpServerTaintWire>;
  /** Plan 10 §2.2 backstop: registered secret VALUES appearing verbatim in text. */
  scanSecretValues?(text: string): Promise<{ hits: Array<{ symbol: string; level: string; how?: "value" | "line" }> }>;
  /** The upload gate (arbiter/policy/file-upload.ts), asked in its unmapped
   *  form by unmapped-upload.ts. Optional only for in-test mocks: without it
   *  the leg withholds every path it finds (fail-closed). The production
   *  adapter always has it; a THROW withholds every path of the call. */
  fileUploadDecision?(req: FileUploadDecisionRequest): Promise<FileUploadDecision>;
  /** Confidentiality plan 15 §3.2: the prompt filter over the user-role
   *  segments of one request (prompt-filter.ts). Optional only for in-test
   *  mocks: the production adapter always has it, and a THROW refuses the
   *  request (fail-closed). */
  filterPrompt?(req: FilterPromptRequest): Promise<FilterPromptResult>;
  /** Reply row reservation (reply-row-reservation.md §3.3, §11.5, §11.7): the
   *  line count of a token's deep-resolved value (one trailing newline
   *  dropped), never the value; with `opts` also `rows`, the screen rows it
   *  wraps to at content width `width`, the head row `first` wide, its TAB
   *  stops counted from the content area's column `indent` (§11.2; absent:
   *  0). OPTIONAL and UTILITY-ONLY: absent, null, a throw or a slow answer
   *  all mean "do not expand". Human plane only. Mirrors
   *  anthropic-proxy/src/arbiter-client.ts. */
  symbolShape?(token: string, opts?: { width: number; first: number; indent?: number }): Promise<SymbolShape | null>;
  /** Reply row reservation §3.6, §11.5: how the reply filter relays this
   *  session's terminal. Null (or absent) means no expansion. Human plane
   *  only. */
  sessionRelay?(sessionKey: string): Promise<SessionRelayState | null>;
  /** Reply row reservation §3.8: record a block the proxy expanded (the
   *  head's token, N, and W/F for a v2 head), so the reply filter can lay
   *  out a continuation row whose head never reached the screen. OPTIONAL
   *  and UTILITY-ONLY. Human plane only. As the anthropic-proxy's. */
  noteReserveBlock?(args: ReserveBlockNote): Promise<void>;
  /** Confidentiality §7.1, "Masked after the fact", across a resume: which
   *  of these tool-call ids an earlier launch's proxy forwarded in clear (the
   *  arbiter's mandu.db). OPTIONAL and UTILITY-ONLY: absent or failing, the
   *  ids are known to this proxy's memory only (no note after a resume, the
   *  mask unchanged). Human plane only. */
  forwardedClear?(ids: string[]): Promise<string[]>;
  /** `forwardedClear` with the store's generation and, given an earlier
   *  answer's, the ids recorded after it (confidentiality.md §7.1, "Two
   *  launches at once"). OPTIONAL and UTILITY-ONLY, human plane only. */
  forwardedClearSince?(ids: string[], since?: number): Promise<ForwardedClearAnswer>;
  /** Record tool-call ids whose result body this proxy forwarded in clear.
   *  Ids only. OPTIONAL and UTILITY-ONLY, human plane only. */
  recordForwardedClear?(ids: string[]): Promise<void>;
  /**
   * Emit an observability event to the arbiter's privileged event log / dashboard
   * (`{op:"emit", event}` → `{seq}`). BEST-EFFORT and OFF THE SECURITY PATH: the
   * proxy always wraps this so a failed/slow emit can never block or fail a
   * request, and never feeds data back toward T-LLM. The raw untrusted bytes an
   * event may carry go ONLY here (privileged side), never upstream.
   */
  emit(event: ArbiterEvent): Promise<EmitResult>;
}

/** The `symbolShape` answer: the value's line count, and with a width its
 *  row count there (reply-row-reservation.md §11.5). Never the value. */
export interface SymbolShape {
  lines: number;
  rows?: number;
  /** With a width: the display width of the value's last row (§14). */
  last?: number;
}

/** A `noteReserveBlock` body (§3.8): tokens and counts, never a value. */
export interface ReserveBlockNote {
  sessionKey: string;
  token: string;
  n: number;
  width?: number;
  first?: number;
}

/** The `sessionRelay` answer (the reply filter's `setSessionRelay` state). */
export interface SessionRelayState {
  mode: "pty" | "pipe" | "passthrough";
  /** The filter can paint reserve blocks. */
  reserve: boolean;
  cols?: number;
  rows?: number;
  /** The filter paints v2 heads (§11.5); absent from a v1 filter. */
  wrap?: boolean;
  /** Where the agent's TUI counts a reply TAB's stops from (§19.7); absent:
   *  `screen`, as Codex does. */
  tabs?: "screen" | "content";
  updatedAt: number;
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package). The real client's `handlingPrompt` returns
 * the bare prompt STRING and takes a bare `mode`; the adapter bridges that into
 * the proxy's `{prompt}` shape. `handlingPrompt` is typed OPTIONAL so the adapter
 * can detect an older arbiter build that predates it and FAIL CLOSED rather than
 * silently skip the handling-prompt injection.
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  classify(req: ClassifyRequest): Promise<ClassifyResult>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  // Takes a bare `mode` plus optional tool-battery capabilities (older
  // clients accept and drop the 2nd arg — absent = full prompt arbiter-side).
  handlingPrompt?(
    mode?: string,
    capabilities?: HandlingPromptCapabilities,
    sessionKey?: string,
  ): Promise<string>;
  // NEW op (arbiter event-emission wave): emit an observability event → {seq}.
  // Optional so the adapter can degrade GRACEFULLY (NOT fail closed) when a
  // arbiter build predates it — emission is best-effort, off the security path.
  /** The real client returns the bare `seq` (arbiter/ipc/client.ts); an older
   *  bridge returned `{seq}`. The adapter normalizes both to `{seq}`. */
  emit?(event: ArbiterEvent): Promise<EmitResult | number>;
  // NEW op (Phase-0 exec gate). Optional so the adapter detects an older arbiter
  // build and THROWS — the proxy then fails closed (block sentinel).
  execGate?(req: ExecGateRequest): Promise<ExecGateDecision>;
  /** Plan 10 §4.2: the confidentiality taint of the process tree behind a
   *  tool call (matched by callId, else by the command's exec signature), and
   *  the output rule the fold chose. Optional: an arbiter predating plan 10
   *  has no taint to report. A THROW is treated as "tainted, rule secret"
   *  (fail-closed) by the caller. The shape is the REAL client's
   *  (`arbiter/ipc/client.ts callTaint(callId, opts)`): a one-object
   *  signature in the anthropic adapter once sent `{callId: {…}}` over the
   *  wire, the arbiter answered "Unknown named parameter 'callId'", and every
   *  live Bash result masked fail-closed (2026-09-24; caught by a battery, not
   *  a test, because the e2e bridge re-shaped the call).
   *  `tests/stack/proxy-real-client-parity.test.ts` pins the
   *  production wiring of THIS adapter too. */
  callTaint?(callId: string, opts?: { command?: string; session?: string; output?: string; codexHead?: boolean; unmappedTool?: string; builtin?: boolean }): Promise<CallTaintWire>;
  /** Plan 13 D9 follow-up: one object, as arbiter/ipc/client.ts declares it. */
  recordCallCommand?(args: { callId: string; command: string; sessionKey?: string }): Promise<{ recorded: boolean; reason?: string }>;
  /** Positional, as arbiter/ipc/client.ts declares it (the parity test pins it). */
  mcpServerTaint?(tool: string, sessionKey?: string): Promise<McpServerTaintWire>;
  scanSecretValues?(text: string): Promise<{ hits: Array<{ symbol: string; level: string; how?: "value" | "line" }> }>;
  /** One request object, as arbiter/ipc/client.ts declares it. */
  fileUploadDecision?(request: FileUploadDecisionRequest): Promise<FileUploadDecision>;
  /** Plan 15 §3.2: one object, as arbiter/ipc/client.ts declares it. */
  filterPrompt?(args: FilterPromptRequest): Promise<FilterPromptResult>;
  // Reply row reservation (reply-row-reservation.md §3.3, §3.6, §11.5).
  // Optional: an arbiter predating them means no expansion (utility, never
  // security). Both are human-plane ops: called on the HUMAN client only.
  symbolShape?(token: string, opts?: { width?: number; first?: number; indent?: number }): Promise<SymbolShape | null>;
  sessionRelay?(sessionKey: string): Promise<SessionRelayState | null>;
  noteReserveBlock?(args: ReserveBlockNote): Promise<void>;
  // Confidentiality §7.1 across a resume: ids only, human plane only.
  forwardedClear?(ids: string[]): Promise<string[]>;
  forwardedClearSince?(ids: string[], since?: number): Promise<ForwardedClearAnswer>;
  recordForwardedClear?(ids: string[]): Promise<{ recorded: number; skipped: number }>;
  /** The per-symbol egress gate (agent-sign-in.md §3.9: the agent-key
   *  release asks it on the HUMAN client, for the `authorization` position). */
  desymbolizationDecision?(req: AuthDesymbolizationRequest): Promise<AuthDesymbolizationDecision>;
  /** The shallow resolve (HUMAN PLANE only): the agent-key release reads the
   *  value after the gate allows it. */
  resolve?(symbol: string): Promise<string | null>;
  close(): void;
}

/** The subset of the arbiter's `DesymbolizationRequest` the agent-key
 *  release sends (anthropic-proxy arbiter-client.ts mirrors it whole). */
export interface AuthDesymbolizationRequest {
  symbol: string;
  boundary: "network";
  destination?: string;
  sessionKey?: string;
  scheme?: "http" | "https";
  positions?: Array<"authorization" | "url" | "header" | "body">;
}

export type AuthDesymbolizationDecision =
  | { allow: true; reason: string }
  | { allow: false; requiresApproval?: boolean; reason: string };

/** The `callTaint` answer (arbiter protocol CallTaintResultWire). */
/** The `mcpServerTaint` answer (arbiter protocol McpServerTaintResultWire). */
export interface McpServerTaintWire {
  verdict: "tainted" | "clean" | "unmapped" | "own";
  server?: string;
  candidates: number;
  level: string | null;
  files: string[];
  apps: string[];
}

export interface CallTaintWire {
  level: string | null;
  files: string[];
  apps: string[];
  rule: "secret" | "clear" | "mask";
  mask: string[];
  root: string | null;
  denied: Array<{ path: string; app: string; reason: string }>;
  /** Plan 10 §11.8, "Refused connections": connections the egress proxy
   *  refused from a process of the tree, by kind (never a host). Explains
   *  only: never lowers a mask. */
  refusedEgress?: Array<{ app: string; kind: string; unattributed?: boolean }>;
  /** Plan 10 §11.8, "Blocked commands": commands of the tree the exec-wrap
   *  shim refused, by program name and kind (never an argument). Explains
   *  only: never lowers a mask. */
  blockedExec?: Array<{ app: string; kind: string }>;
  /** Plan 10 §11.8: the output is (part of) this file's structured twin,
   *  or exactly its whole-file twin (`twinWhole`). */
  twinOf?: string[];
  /** Plan 10 §11.8, "A document's own twin": the output is exactly the
   *  file's whole-file twin (its base symbol, after Codex's head). */
  twinWhole?: boolean;
  /** Plan 10 §11.8, "A key listing" (2026-10-16): the output holds
   *  no token and is the keys of the file's structured twin, in order. */
  twinKeys?: boolean;
  /** Plan 10 §11.13, "A config with no secret" (2026-10-17): the output
   *  holds no token and is a piece of the file's own-text twin. */
  twinOwn?: boolean;
  /** Plan 10 §11.8, "A folder's names" (2026-10-17): with `twinOf` (the
   *  paths listed), the output is exactly a plain `ls` of those folders. */
  dirListing?: boolean;
  /** With the confidentiality axis on: `tree` (the guard tied the call to
   *  a process tree) or `session` (it did not, and the session holds a raw
   *  read: plan 10 §11.12 for an `unmappedTool`, plan 13 D7 for a shell
   *  call the call-root recorder could not bind; the fields are every raw
   *  secret read of the session). */
  evidence?: "tree" | "session" | "unmapped";
  /** With `evidence: "unmapped"` (plan 10 §11.18): why the whole result
   *  is hidden and how to let it through (product copy). */
  why?: string;
}

/**
 * Adapter: present the real arbiter IPC client as a `Arbiter`. Used at deployment
 * (src/server-main.ts), never in tests. If the connected arbiter predates
 * handlingPrompt, the adapter throws on use — which the proxy treats as a arbiter
 * error and FAILS CLOSED (refuses the request) rather than leaking.
 */
export class ArbiterClientAdapter implements Arbiter {
  /** `human`: a client on the arbiter's human-plane socket
   *  (arbiter-human-plane.md), used for `symbolShape` and `sessionRelay`,
   *  which the data socket refuses (absent → both answer null, and the proxy
   *  does not expand: reply-row-reservation.md §5.3, §11.5, §11.7), and for
   *  `execGate`, `recordCallCommand` and `callTaint`, whose records the
   *  arbiter believes only from a channel the agent's processes cannot reach
   *  (confidentiality plan 13 §3 D9), and `fileUploadDecision`, which the
   *  arbiter answers only there. Absent → those go to the data socket,
   *  where no call is bound: every shell result is masked while the session
   *  holds a raw read (fail-closed). As the anthropic-proxy adapter. */
  constructor(
    private readonly client: RealArbiterClient,
    private readonly human?: Pick<RealArbiterClient, "symbolShape" | "sessionRelay" | "noteReserveBlock"> & Partial<Pick<RealArbiterClient, "execGate" | "callTaint" | "recordCallCommand" | "emit" | "filterPrompt" | "forwardedClear" | "forwardedClearSince" | "recordForwardedClear" | "desymbolizationDecision" | "resolve" | "fileUploadDecision">>,
  ) {}

  /**
   * Agent-sign-in.md §3.9: the agent's own key for an auth header, as the
   * anthropic-proxy adapter asks it. The gate and the resolve both ride the
   * HUMAN client, never the data socket. No human client, or one without
   * either op ⇒ null: the placeholder stays. A throw propagates (the caller
   * keeps the placeholder).
   */
  async authCredential(req: { symbol: string; destination: string; scheme: "http" | "https"; sessionKey?: string }): Promise<{ value: string | null; reason: string }> {
    const h = this.human;
    if (!h?.desymbolizationDecision || !h.resolve) return { value: null, reason: "no human plane: the key is not put back" };
    const d = await h.desymbolizationDecision({
      symbol: req.symbol, boundary: "network", destination: req.destination, scheme: req.scheme,
      positions: ["authorization"],
      ...(req.sessionKey ? { sessionKey: req.sessionKey } : {}),
    });
    if (!d.allow) return { value: null, reason: d.reason };
    const value = await h.resolve(req.symbol);
    return value === null ? { value: null, reason: "the symbol did not resolve" } : { value, reason: d.reason };
  }

  async classify(req: ClassifyRequest): Promise<ClassifyResult> {
    return this.client.classify(req);
  }

  async symbolize(args: SymbolizeArgs): Promise<string> {
    return this.client.symbolize(args);
  }

  async handlingPrompt(args?: HandlingPromptArgs): Promise<{ prompt: string }> {
    if (!this.client.handlingPrompt) {
      throw new Error(
        "arbiter does not implement handlingPrompt (op not yet landed) — fail closed",
      );
    }
    const prompt = await this.client.handlingPrompt(args?.mode, args?.capabilities, args?.sessionKey);
    return { prompt };
  }

  async emit(event: ArbiterEvent): Promise<EmitResult> {
    // Emission is BEST-EFFORT and off the security path. Unlike handlingPrompt /
    // symbolize, a arbiter that predates `emit` must NOT fail the request — we
    // degrade to a no-op (seq:-1). The proxy additionally wraps every emit in its
    // own try/catch, so this never throws toward the request path either.
    // arbiter-human-plane.md §10.2: on the human client when there is one,
    // where the event is believed; else (or on a failure there) the data
    // socket, where the arbiter stores it as a claim.
    if (this.human?.emit) {
      try {
        const r = await this.human.emit(event);
        return typeof r === "number" ? { seq: r } : r;
      } catch { /* the data socket below */ }
    }
    if (!this.client.emit) return { seq: -1 };
    const r = await this.client.emit(event);
    return typeof r === "number" ? { seq: r } : r;
  }

  async execGate(req: ExecGateRequest): Promise<ExecGateDecision> {
    // Plan 13 D9: on the human client when there is one.
    const via = this.human?.execGate ? this.human : this.client;
    if (!via.execGate) {
      throw new Error(
        "arbiter does not implement execGate (op not yet landed) — fail closed",
      );
    }
    return via.execGate(req);
  }

  async mcpServerTaint(req: { tool: string; sessionKey?: string }): Promise<McpServerTaintWire> {
    // An arbiter predating plan 10 §11.13 maps no server: each proxy keeps its older rule.
    if (!this.client.mcpServerTaint) return { verdict: "unmapped", candidates: 0, level: null, files: [], apps: [] };
    return this.client.mcpServerTaint(req.tool, req.sessionKey);
  }

  async callTaint(req: { callId: string; command?: string; sessionKey?: string; output?: string; codexHead?: boolean; unmappedTool?: string; builtin?: boolean }): Promise<CallTaintWire> {
    // Plan 13 D9: on the human client when there is one.
    const via = this.human?.callTaint ? this.human : this.client;
    if (!via.callTaint) {
      // An arbiter predating plan 10 has no process taint: nothing to render.
      return { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
    }
    return via.callTaint(req.callId, { ...(req.command ? { command: req.command } : {}), ...(req.sessionKey ? { session: req.sessionKey } : {}), ...(req.output ? { output: req.output } : {}), ...(req.codexHead === true ? { codexHead: true } : {}), ...(req.unmappedTool ? { unmappedTool: req.unmappedTool } : {}), ...(req.builtin === true ? { builtin: true } : {}) });
  }

  async recordCallCommand(req: { callId: string; command: string; sessionKey?: string }): Promise<{ recorded: boolean }> {
    // Plan 13 D9 follow-up: on the human client when there is one (the data
    // socket records nothing). An arbiter predating the op records nothing.
    const via = this.human?.recordCallCommand ? this.human : this.client;
    if (!via.recordCallCommand) return { recorded: false };
    const r = await via.recordCallCommand({ callId: req.callId, command: req.command, ...(req.sessionKey ? { sessionKey: req.sessionKey } : {}) });
    return { recorded: r.recorded === true };
  }

  async symbolShape(token: string, opts?: { width: number; first: number; indent?: number }): Promise<SymbolShape | null> {
    // Utility-only: without the human plane (or an arbiter predating the op)
    // there is no shape to give. Never the data socket: it refuses the op.
    if (!this.human?.symbolShape) return null;
    // The real client's shape: (token, {width, first, indent?}), positional
    // token. `indent` only when given.
    const r = opts
      ? await this.human.symbolShape(token, {
          width: opts.width, first: opts.first, ...(opts.indent !== undefined ? { indent: opts.indent } : {}),
        })
      : await this.human.symbolShape(token);
    if (!r || typeof r.lines !== "number") return null;
    return {
      lines: r.lines,
      ...(typeof r.rows === "number" ? { rows: r.rows } : {}),
      ...(typeof r.last === "number" ? { last: r.last } : {}),
    };
  }

  async sessionRelay(sessionKey: string): Promise<SessionRelayState | null> {
    // Utility-only, and human plane only (§11.5): without the human client,
    // or an arbiter predating the op, there is no relay; no expansion.
    if (!this.human?.sessionRelay) return null;
    return (await this.human.sessionRelay(sessionKey)) ?? null;
  }

  async noteReserveBlock(args: ReserveBlockNote): Promise<void> {
    // Utility-only, human plane only (§3.8): without the human client, or an
    // arbiter predating the op, nothing is recorded (a headless block's rows
    // then paint blank). The real client takes the body object whole.
    if (!this.human?.noteReserveBlock) return;
    await this.human.noteReserveBlock({
      sessionKey: args.sessionKey, token: args.token, n: args.n,
      ...(args.width !== undefined ? { width: args.width, first: args.first ?? args.width } : {}),
    });
  }

  async forwardedClear(ids: string[]): Promise<string[]> {
    // Utility-only, human plane only (confidentiality.md §7.1, "Masked after
    // the fact"): without the human client, or an arbiter predating the op,
    // no earlier launch's ids are known (no note after a resume).
    if (!this.human?.forwardedClear) return [];
    return this.human.forwardedClear(ids);
  }

  async forwardedClearSince(ids: string[], since?: number): Promise<ForwardedClearAnswer> {
    // Utility-only, human plane only ("Two launches at once"): without the
    // human client's op, the plain ask (no generation: an id unknown at its
    // first ask stays unknown, the behavior before).
    if (!this.human?.forwardedClearSince) return { ids: await this.forwardedClear(ids) };
    return this.human.forwardedClearSince(ids, since);
  }

  async recordForwardedClear(ids: string[]): Promise<void> {
    // Utility-only, human plane only: without it the ids stay in this
    // proxy's memory. Positional array, as arbiter/ipc/client.ts takes it.
    if (!this.human?.recordForwardedClear) return;
    await this.human.recordForwardedClear(ids);
  }

  async scanSecretValues(text: string): Promise<{ hits: Array<{ symbol: string; level: string; how?: "value" | "line" }> }> {
    if (!this.client.scanSecretValues) throw new Error("arbiter does not implement scanSecretValues — the value backstop cannot run");
    return this.client.scanSecretValues(text);
  }

  async fileUploadDecision(req: FileUploadDecisionRequest): Promise<FileUploadDecision> {
    // On the human client when there is one, as the anthropic-proxy adapter:
    // the arbiter reads the session's mapping and the file only for an ask
    // from there; a data-socket claim is answered `fs:upload-unattested`, a
    // refusal (so a proxy without the human plane withholds every path).
    const via = this.human?.fileUploadDecision ? this.human : this.client;
    if (!via.fileUploadDecision) {
      throw new Error("arbiter does not implement fileUploadDecision (op not yet landed) — fail closed");
    }
    return via.fileUploadDecision(req);
  }

  async filterPrompt(req: FilterPromptRequest): Promise<FilterPromptResult> {
    // Plan 15 §7 (phase 3): on the human client when there is one. Only an
    // attested caller is held for the human's answer and has a verdict
    // consulted (plan 13 D9); from the data socket an `ask` goes with its
    // default (fail-closed: never raw).
    const via = this.human?.filterPrompt ? this.human : this.client;
    // An arbiter without the op cannot filter the prompt: throw, and the
    // rewrite refuses the request (the text is never forwarded unfiltered).
    if (!via.filterPrompt) throw new Error("arbiter does not implement filterPrompt — the prompt filter cannot run");
    return via.filterPrompt({
      ...(req.session ? { session: req.session } : {}),
      agent: req.agent,
      segments: req.segments.map((s) => ({ id: s.id, origin: s.origin, text: s.text })),
      ...(req.holds === true ? { holds: true } : {}),
      ...(typeof req.heldMs === "number" ? { heldMs: req.heldMs } : {}),
    });
  }
}
