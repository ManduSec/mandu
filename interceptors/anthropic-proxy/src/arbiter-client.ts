/**
 * arbiter-client — the arbiter dependency the model proxy speaks to.
 *
 * Mandu Track A (interceptors/anthropic-proxy). The proxy never opens the symbol-
 * table DB directly: the arbiter (arbiter/) is the single owner of the symbol
 * table + policy engine, and we call it over its Unix-socket NDJSON IPC. This
 * module defines the NARROW interface the proxy needs (`Arbiter`) plus a thin
 * adapter (`ArbiterClientAdapter`) that fulfils it via the real arbiter IPC
 * client (arbiter/ipc/client.ts).
 *
 * Decoupling rationale: the proxy is written against `Arbiter`, not against the
 * concrete client. Tests inject a MockArbiter (test/helpers/mock-arbiter.ts) so
 * the suite does not depend on the arbiter daemon (or the two new ops the arbiter
 * sub-agent is adding in parallel) actually landing. At integration time the
 * adapter below wires the real client.
 *
 * The op shapes mirror arbiter/ipc/protocol.ts and arbiter/policy/policy-
 * interface.ts exactly:
 *   - classify({tool, field?, value, boundary, origin?, params?}) → {trust,...}
 *   - symbolize({tool, value, field?, origin?, sessionKey?, callId?}) → symbol
 *   - handlingPrompt({mode?})                                        → {prompt}
 *   - recordToolCall({toolUseId, name, input, sessionKey?})          → {ok:true}
 *
 * `handlingPrompt` and `recordToolCall` are the TWO NEW OPS the arbiter sub-agent
 * is adding in parallel; we code against their agreed contracts here.
 */

/**
 * The `$MDU:*` symbol pattern, mirrored locally from arbiter/symbol-table/
 * symbol-format.ts `MDU_SYM_FORMAT.pattern`. The proxy is dependency-free of the
 * arbiter package, so we keep this in sync here rather than import it. Used by the
 * §9 oracle predicate (src/events.ts) to strip symbol tokens when checking that
 * no un-symbolized untrusted byte survived in the forwarded prompt.
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
  /** The SAME origin, spelled in the arbiter's world — HumanView (Plan 9). The
   *  agent echoes the AgentView twin it executed; every path policy the arbiter
   *  owns (catalog, user labels, derived labels) is keyed in HumanView. Consumed
   *  ONLY by the confidentiality derivation — TRUST never sees it, so a spelling
   *  translation can never move a datum UNTRUSTED → TRUSTED. */
  originHuman?: string;
  params?: Record<string, unknown>;
  /** The path-ish params in the arbiter's world (HumanView). Needed alongside
   *  `originHuman` because the confidentiality derivation takes the MAX over the
   *  origin AND the params — so an untranslated param keeps hitting the catalog on
   *  its BASENAME and overrides the human's label. Confidentiality-only, like
   *  `originHuman`: TRUST still reads `params`. */
  paramsHuman?: Record<string, unknown>;
  /** The launch directory the agent resolves a relative path in a typed path
   *  field against (MANDU_AGENT_CWD, HumanView), sent only for a tool the
   *  session's gate surface lists in `paths` under `relativeBase: "launch"`.
   *  The arbiter reads it only in the confidentiality derivation, and only
   *  where its own copy of that surface agrees (policy-interface.ts
   *  `relativePathBase`; confidentiality.md §6). */
  relativeBase?: string;
  /** MEASURED FACT (this proxy is the only component holding the conversation):
   *  the whole candidate span — `value` modulo one trailing newline — appears
   *  CONTIGUOUSLY in this request's trusted, already-model-visible bytes
   *  (rewrite-request.ts buildTrustedContextHaystack: system + user/assistant
   *  text + tool_use args, NEVER tool_result bodies). Consumed only by the
   *  arbiter's exact-match upgrade (exec-routing.md §8.4 rung 1); absent ⇒
   *  the upgrade never fires. */
  verbatimInTrustedContext?: boolean;
  /** The originating tool_use id of the tool_result being classified — the
   *  arbiter's correlation key to per-invocation runtime state it recorded
   *  (today: the rung-2 exec CLEAN verdicts, hash-bound). Absent ⇒ no
   *  correlation-keyed rule fires. */
  callId?: string;
  /** Session identity for SESSION-KEYED spec resolution (agent-e2e-harness.md
   *  §7.1): the same key `symbolize` carries (MANDU_SESSION_KEY / scopeId).
   *  A session bound via the arbiter's `setSessionSpec` op classifies against
   *  that agent's inbound spec; absent/unbound falls back to the arbiter's
   *  process-global boot spec. */
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
   *  beside a `value-backstop` raise: the value with each span replaced by
   *  its symbol. Taken only through `acceptValueOnlyOffer` and only when the
   *  call's own evidence is clean; else the result is masked whole. */
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
  /** The launch directory a relative typed-path origin was read in, as on
   *  the result's classify (ClassifyArgs.relativeBase): the arbiter stores
   *  the row at the resolved path, so its level and bindings are that
   *  file's label (SymbolizeRequest.relativeBase). */
  relativeBase?: string;
  sessionKey?: string;
  callId?: string;
  /** Confidentiality level to store (the arbiter re-derives and takes max). */
  confidentiality?: string;
  /** Integrity half of the label; only "trusted" counts server-side. */
  integrity?: string;
  /** `"claude-task"`: the value is a Claude Code background-task poll's
   *  WHOLE result (`BashOutput` / `TaskOutput`), led by the status tags its
   *  runtime writes; the arbiter, matching them by its own grammar at offset
   *  0, does not fingerprint them as lines of the registered value (plan 10
   *  §11.14). `"write-notice"`: a write tool's whole result, led by the
   *  agent's fixed success notice for the call's own path (plan 15 §13.10). */
  resultHead?: "claude-task" | "write-notice";
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
  /** The mandu-policy MCP tools are in the battery (policy-surface.md §8
   *  §5.1). ABSENT = false on the arbiter side: only an up-to-date mount has them. */
  manduPolicy?: boolean;
  /** A shell/exec tool is in the battery. */
  exec?: boolean;
  /** The exec tool's declared input_schema has an `env` property — the
   * RESTRICTED=1 opt-in is expressible on this runtime. Reported FALSE only
   * when every detected exec tool has a well-formed schema that provably
   * lacks `env` (Claude Code's Bash: the harness rejects the whole call with
   * InputValidationError, so the guidance would be a per-call trap). */
  execEnv?: boolean;
  /** The file view is active (a ViewMap with an AgentView root): untrusted
   * workspace files are whole-file symbol twins on the agent's disk. Gates
   * handling-prompt rule R9 (symbol-twin-shell-blindness.md §4.5). Not a
   * tool fact — the proxy reports it from its own configuration. */
  fsView?: boolean;
  /** The session's secret posture (src/secret-posture.ts; env
   * MANDU_SECRET_POSTURE, set by the launcher). `read-blocked` (macOS) adds
   * the "blocked credential files" section with the confidentiality axis ON.
   * Not a tool fact; reported only when set (absent = the byte-identical
   * prompt, docs/design/agents/handling-prompt.md §2). */
  secretPosture?: string;
}

/** Request for the (new) handlingPrompt op. */
export interface HandlingPromptArgs {
  /** Optional handling-prompt mode (e.g. strict/lenient). Arbiter-defined. */
  mode?: string;
  /** Tool-battery capability facts (see HandlingPromptCapabilities). */
  capabilities?: HandlingPromptCapabilities;
  /** The session the prompt is for (plan 11 phase 3): the arbiter reads its
   *  main-model binding. Absent = the strict (outside model) text. */
  sessionKey?: string;
}

/** Request for the (new) recordToolCall op. */
export interface RecordToolCallArgs {
  toolUseId: string;
  name: string;
  input: unknown;
  sessionKey?: string;
}

/** Mirrors arbiter/policy/rule-ref.ts `RuleRef` — decision provenance
 * (policy-surface.md §9.3): which standing rule / human verdict / fail-closed
 * default produced a usage decision. Rides events as `policy.ruleRef`. */
export interface RuleRef {
  source: "rule" | "verdict" | "fail-closed";
  id: string;
}

/** Mirrors arbiter/policy/fs-outbound.ts `FsPathDecisionRequest` (P3 gate). */
export interface FsPathDecisionRequest {
  tool: string;
  path: string;
  mode: "read" | "write";
  workspaceRoots: string[];
  /** ATTRIBUTION-ONLY (never a decision input): rides to the approval-queue
   * row so the arbiter can attribute it to a session. Additive; old arbiters
   * ignore it. */
  sessionKey?: string;
}

/** Mirrors arbiter/policy/fs-outbound.ts `FsPathDecision`. */
export type FsPathDecision =
  | { allow: true; reason: string; ruleRef?: RuleRef }
  | {
      allow: false;
      requiresApproval: boolean;
      reason: string;
      ruleRef?: RuleRef;
      /** The approval-queue row this deny created/bumped (`egr-<n>`) — rides
       * events as `policy.approvalId`, the Pending-tab join
       * (policy-surface.md §9.5). */
      approvalId?: string;
    };

/** Mirrors arbiter/policy/file-upload.ts `FileUploadDecisionRequest`: may
 *  `tool` send the bytes of the absolute HumanView `path` to `destination`
 *  (upload-gate.ts; Claude Code's DesignSync)? */
export interface FileUploadDecisionRequest {
  tool: string;
  path: string;
  /** "" when the host is not known (the unmapped form). */
  destination: string;
  /** More hosts the bytes may reach: a binding must name each. */
  destinations?: readonly string[];
  /** The bytes go to a model (OpenClaw's view_image, image, pdf, media
   *  generators): a file at `any-model` may go, whatever its bindings. */
  toModel?: boolean;
  /** The unmapped form (unmapped-upload.ts): a path in the input of a tool
   *  no gate table names; the arbiter reads the session's mapping first. */
  unmapped?: boolean;
  /** The approval row's session (and, in the unmapped form, whose mapping
   *  and guard the arbiter reads). */
  sessionKey?: string;
}

/** Mirrors arbiter/policy/file-upload.ts `FileUploadDecision` (the
 *  sensitive-path gate's shape). */
export type FileUploadDecision = FsPathDecision;

/** Mirrors arbiter/policy/exec-gate.ts `ExecGateRequest`. */
export interface ExecGateRequest {
  /** The raw shell command as the model wrote it (symbols still opaque). */
  command: string;
  /** Working directory the command would run in. */
  cwd?: string;
  /** The session the command belongs to. LOAD-BEARING since Plan 8: the arbiter
   *  tightens exec in a HIGH session (one that has read secret content into
   *  context), and without a sessionKey it cannot tell — so it treats the call
   *  as unattributable and does not gate. The proxy omitted this field until the
   *  watermark landed, which made the high-session exec block dead in the real
   *  stack while passing every arbiter-side test. */
  sessionKey?: string;
  /** The tool_use id this command belongs to (only the proxy knows it). The
   *  arbiter records it with the signature-keyed decision so the exec
   *  supervisor learns which callId to key its clean-verdict report on
   *  (exec-routing.md §8.5). Utility-only correlation — the verdict's hash
   *  binding carries the security. */
  callId?: string;
}

/** Mirrors arbiter/policy/session-egress.ts (Plan 8, §4). */
export interface SessionEgressRequest {
  sessionKey?: string;
  boundary: "network" | "shell" | "filesystem";
  /** The sink. Absent ⇒ cannot be proven bound ⇒ fail-closed to approval. */
  destination?: string;
  netEnabled?: boolean;
}

export interface SessionEgressDecision {
  allow: boolean;
  requiresApproval: boolean;
  reason: string;
  ruleRef?: RuleRef;
  /** The Approvals row the refusal filed or bumped (confidentiality.md §4,
   *  "The human half", 2026-10-11): the net gate puts the call on the
   *  asked sentinel and the deny event carries it as `policy.approvalId`. */
  approvalId?: string;
}

/** Mirrors arbiter/policy/policy-interface.ts `DesymbolizationRequest` — the
 *  per-symbol data-USAGE gate. The proxy only ever asks at the `network`
 *  boundary (net-gate.ts, the per-symbol leg); it never resolves a symbol. */
export interface DesymbolizationRequest {
  symbol: string;
  boundary: "network";
  /** The sink host. Absent ⇒ cannot be proven bound/trusted ⇒ approval. */
  destination?: string;
  asCommand?: boolean;
  sessionKey?: string;
  /** A pre-check: the net-proxy judges the release again on the wire and
   *  spends a human's *Allow once* there; this ask reads it unspent
   *  (arbiter-human-plane.md §10.3). */
  preflight?: boolean;
  /** The scheme the request travels in (the agent-key release states its
   *  upstream's, agent-sign-in.md §3): a key granted for https is never put
   *  back in plain HTTP (plan 10 §11.13.1). */
  scheme?: "http" | "https";
  /** Where in the request the symbol sits (mirrors the arbiter's
   *  `RequestPosition`). The agent-key release states `authorization`: it
   *  writes the auth header alone, and a key bound only by its auth grant
   *  is refused anywhere else (plan 10 §11.13.1, 2026-10-09). The network
   *  pre-check (net-gate.ts) states none, so such a key is refused there. */
  positions?: Array<"authorization" | "url" | "header" | "body">;
}

export type DesymbolizationDecision =
  | { allow: true; reason: string; ruleRef?: RuleRef }
  | { allow: false; requiresApproval?: boolean; reason: string; ruleRef?: RuleRef; approvalId?: string };

/** Mirrors arbiter/ipc/protocol.ts `labelWrittenPath` (Plan 9, §4/§8). */
export interface LabelWrittenPathRequest {
  sessionKey?: string;
  /** The absolute HumanView path about to be written. */
  path: string;
  tool?: string;
}

export interface LabelWrittenPathResult {
  /** Did this write mint (or raise) a derived on-disk label? */
  labeled: boolean;
  /** The session is HIGH and the write could NOT be labeled ⇒ the caller must
   *  FAIL CLOSED (deny the write). Distinct from `!labeled`, which also covers
   *  the benign "nothing to persist" of a public session — collapsing the two is
   *  how this ships silently fail-open. */
  refused: boolean;
  /** The level a FUTURE session will now classify this path at. */
  level: string;
  /** Always empty on a derived row: a machine may taint, never grant a release. */
  bindings: string[];
  reason: string;
}

/** Mirrors arbiter/policy/exec-gate.ts `ExecGateEvasion`. */
export interface ExecGateEvasion {
  kind: "absolute_path_net_tool" | "env_prefix_override";
  evidence: string;
}

/** Mirrors arbiter/policy/exec-gate.ts `ExecGateResult` (model-context exec
 * gate, exec-routing.md §3). `block` means an untrusted symbol sits in a
 * command/execution position; `allow` leaves data-position symbols opaque. */
export interface ExecGateDecision {
  decision: "allow" | "block";
  reason: string;
  symbols: string[];
  evasion: ExecGateEvasion[];
  shell: "AgentShell" | "HumanShell";
  identifier: string | null;
  ruleRef?: RuleRef;
  /** The approval-queue entry id when the PROVENANCE half of the gate
   * (exec-routing.md §8.7a: net-fetched program text) blocked pending a
   * human verdict — the same field the fs / net decisions carry. */
  approvalId?: string;
  /** The net-fetched program text the provenance gate decided on (`(stdin)`
   * for a `curl | bash` pipe) and the host its bytes came from. */
  programText?: { path: string; originHost: string };
  /** ALLOW only: the command with each secret placeholder the agent's shell
   * would expand requoted, so the program receives it whole (arbiter
   * shell-placeholder-quoting.ts; confidentiality.md §7). Delivered in place
   * of a shell tool's command (exec-gate.ts). Absent when nothing needs it. */
  requoted?: string;
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

/** Who wrote a segment of user-role text (confidentiality-plan-15 §3.1). */
export type PromptSegmentOrigin = "human" | "harness" | "side-call";

/** The `filterPrompt` request (plan 15 §3.2). Never a dry run from a proxy:
 *  that is the dashboard's, on the human plane. */
/** Secret-discovery.md §2.8: a PDF `document` block, and the path the tool
 *  read it from (HumanView spelling). */
export interface DocumentTextRequest {
  data: string;
  mediaType: string;
  origin?: string;
  sessionKey?: string;
}

/** The text the block is forwarded as (null: masked whole), as the arbiter
 *  answers it (`arbiter/ipc/protocol.ts` DocumentTextResultWire). */
export interface DocumentTextAnswer {
  text: string | null;
  twinOf?: string;
  reason: string;
}

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

/** One finding as the arbiter reports it: offsets into the segment's text,
 *  the category and filter, the action, the symbol that replaced it. */
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

/** The arbiter's answer (mirrors arbiter/ipc/protocol.ts FilterPromptResultWire). */
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

/**
 * The narrow arbiter surface the model proxy depends on. Anything that satisfies
 * this — the real adapter or a mock — can drive the proxy.
 */
export interface Arbiter {
  classify(req: ClassifyRequest): Promise<ClassifyResult>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  /** Fetch the handling system prompt to inject so T-LLM treats symbols as
   * opaque. (NEW arbiter op — coded against the agreed contract.) */
  handlingPrompt(args?: HandlingPromptArgs): Promise<{ prompt: string }>;
  /** Session-health (dashboard.md §4.21): which advertised tool names the
   *  session's inbound spec does not know. Utility surface; an arbiter that
   *  predates the op answers "none unknown" (the adapter degrades). */
  toolSurface(names: string[], sessionKey?: string): Promise<{ unknown: string[] }>;
  /** The per-agent gate surface for a session (gate-surface.ts): which tool is
   *  the shell / reaches the network / carries paths, and through which field.
   *  Optional: an arbiter that predates the op leaves the union of every
   *  agent's table in force (gate-surface.ts GateSurfaceCache). */
  gateSurface?(req: { sessionKey?: string }): Promise<unknown>;
  /** Record a reconstructed tool_use decision for OS-interceptor correlation.
   * (NEW arbiter op — coded against the agreed contract.) */
  recordToolCall(args: RecordToolCallArgs): Promise<{ ok: true }>;
  /** Sensitive-path gate (P3, fs-sync.md §1.4.1): may this tool touch
   * this absolute out-of-workspace path? The proxy treats a THROW as
   * unreachable and fails closed (denied-sentinel), never open. */
  fsPathDecision(req: FsPathDecisionRequest): Promise<FsPathDecision>;
  /** The local-file upload gate (upload-gate.ts; arbiter file-upload.ts):
   * may this tool send this file's bytes to this host? OPTIONAL in the type
   * only so narrow test doubles need not carry it: when a call uploads a
   * file and the op is absent, the upload gate REFUSES the call. A THROW is
   * unreachable ⇒ refuse. */
  fileUploadDecision?(req: FileUploadDecisionRequest): Promise<FileUploadDecision>;
  /** Model-context exec gate (exec-routing.md §3): classify a `Bash`/shell
   * command and decide allow/block (blocks only an untrusted symbol in
   * command/execution position). The proxy treats a THROW as unreachable and
   * fails closed (block sentinel), never open. */
  execGate(req: ExecGateRequest): Promise<ExecGateDecision>;
  /**
   * The SESSION high-watermark gate (Plan 8, confidentiality.md §4). Consulted
   * IN ADDITION to the per-symbol egress gate, because a PARAPHRASE CARRIES NO
   * SYMBOL: once the model has read secret content into context, it can
   * re-encode it into a URL with no `$MDU:*` token in it, and the per-symbol
   * gate is structurally blind to that.
   *
   * OPTIONAL — an arbiter predating Plan 8 lacks the op, in which case the net
   * gate does not gate (that arbiter has no watermark to enforce, so there is
   * nothing to fail closed ABOUT). A THROW, by contrast, is treated as
   * unreachable and fails closed to a block.
   */
  sessionEgressDecision?(req: SessionEgressRequest): Promise<SessionEgressDecision>;
  /**
   * The per-symbol data-usage verdict for a symbol the model put in a NETWORK
   * tool's destination field (net-gate.ts, the per-symbol leg). OPTIONAL in the
   * type only so narrow test doubles need not carry it: when a symbol IS
   * present and the op is absent, the net gate BLOCKS (it cannot judge the
   * flow). A THROW is unreachable ⇒ block.
   */
  desymbolizationDecision?(req: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  /**
   * The agent's own key for the auth header of a request to `destination`
   * (agent-sign-in.md §3, auth-substitution.ts): the egress gate's verdict
   * for the placeholder at that host and, on allow, its value, both on the
   * human plane. OPTIONAL: absent (a test double, no human plane) ⇒ the
   * placeholder stays and the provider answers 401.
   */
  authCredential?(req: { symbol: string; destination: string; scheme: "http" | "https"; sessionKey?: string }): Promise<{ value: string | null; reason: string }>;
  /**
   * The ON-DISK label a HIGH session's write leaves behind (Plan 9,
   * confidentiality.md §4/§8): the arbiter records the session's watermark on the
   * path being written, so a FUTURE session classifies the derived file at that
   * level instead of `public`. This is what makes the watermark survive the
   * session — see fs-label.ts.
   *
   * OPTIONAL, on the same argument as `sessionEgressDecision`: an arbiter
   * predating Plan 9 has no derived-label store, so there is nothing to record
   * and nothing to fail closed ABOUT. A THROW is different — that is an arbiter
   * we cannot reach, and the caller DENIES the write.
   */
  labelWrittenPath?(req: LabelWrittenPathRequest): Promise<LabelWrittenPathResult>;
  /**
   * The exec box's symbol-twin hints for a model-authored command
   * (symbol-twin-shell-blindness.md §4.1 v2): the AgentView paths recent boxed
   * AgentShell leaves of this command named whose twin is solely symbol
   * tokens. OPTIONAL and UTILITY-ONLY: an arbiter predating the op, a throw,
   * or a slow answer all mean "no hints" — the note then rests on the command
   * parse alone. The proxy re-verifies every hint under its own roots.
   */
  execTwinsFor?(command: string): Promise<{ twins: { asTyped: string; abs: string }[]; more?: number }>;
  /** Plan 10 §4.2: the confidentiality taint of the process tree behind a
   *  tool call (matched by callId, else by the command's exec signature), and
   *  the output rule the fold chose. Optional: an arbiter predating plan 10
   *  has no taint to report. A THROW is treated as "tainted, rule secret"
   *  (fail-closed) by the caller. */
  callTaint?(req: { callId: string; command?: string; sessionKey?: string; output?: string; unmappedTool?: string; forPoll?: string }): Promise<CallTaintWire>;
  /** Plan 13 D9 follow-up: the command the proxy DELIVERED to the agent for a
   *  call (after its view map and gates), recorded before the call is
   *  relayed; `callTaint` binds the call to the agent's shell by it, never by
   *  the text the agent echoes back. Optional: without it (or on a throw)
   *  the call is bound by execGate's record alone, which the view map's
   *  rewrite may make miss: the result is then masked while the session
   *  holds a raw read (fail-closed). */
  recordCallCommand?(req: { callId: string; command?: string; sessionKey?: string }): Promise<{ recorded: boolean }>;
  /** supported-agents.md §2.3 item 7: label one exact path `no-model` for
   *  this session, in memory (arbiter session-path-labels.ts). The proxy
   *  registers OpenCode 2's background output file before the model reads
   *  the result that names it. Optional: an arbiter without it (or a throw)
   *  makes the proxy mask that result whole (fail-closed). */
  sessionPathLabel?(req: { path: string; sessionKey: string; reason?: string }): Promise<{ labeled: boolean; path: string | null }>;
  /** Confidentiality plan 13 §4.5.1: per tool result of a request, the level
   *  the agent's OWN connections to a holder mask it at (an HTTP MCP server
   *  or a local dev server that read a secret, which the agent itself
   *  reached). One batch per request; the first ask of a call ends its
   *  window. Optional: an arbiter without it masks nothing by this leg. A
   *  THROW refuses the request (fail-closed). */
  agentReceiptTaint?(req: { calls: Array<{ callId: string; tool: string }>; sessionKey?: string }): Promise<AgentReceiptTaintWire>;
  /** Plan 10 §11.13: the taint of the stdio MCP server behind `tool`, mapped
   *  by the argv the launcher registered and the guard recorded. Optional: an
   *  arbiter without it maps nothing (every server unmapped). A THROW is
   *  treated as tainted (fail-closed) by the caller. */
  mcpServerTaint?(req: { tool: string; sessionKey?: string }): Promise<McpServerTaintWire>;
  /** Plan 10 §2.2 backstop: registered secret VALUES appearing verbatim in text. */
  scanSecretValues?(text: string): Promise<{ hits: Array<{ symbol: string; level: string; how?: "value" | "line" }> }>;
  /** Secret-discovery.md §2.8, "A document block": the text a PDF
   *  `document` block of a tool result is forwarded as, or null (the result
   *  is then masked whole, as any non-text result). Optional: an arbiter
   *  without it leaves every such result masked whole. A THROW is treated
   *  as null (fail-closed). */
  documentText?(req: DocumentTextRequest): Promise<DocumentTextAnswer>;
  /** Confidentiality plan 15 §3.2: the prompt filter over the user-role
   *  segments of one request (prompt-filter.ts). Optional only for in-test
   *  mocks: the production adapter always has it, and a THROW refuses the
   *  request (fail-closed: the text is never forwarded unfiltered). */
  filterPrompt?(req: FilterPromptRequest): Promise<FilterPromptResult>;
  /** Reply row reservation (reply-row-reservation.md §3.3, §11.5): the line
   *  count of a token's deep-resolved value (one trailing newline dropped),
   *  never the value; with `opts` also `rows`, the screen rows it wraps to at
   *  content width `width`, the head row `first` wide, under the TUI's wrap
   *  `rule` (§17; absent: `ink`), its TAB stops counted from the content
   *  area's column `indent` (§11.2; absent: 0). OPTIONAL and
   *  UTILITY-ONLY: absent, null, a throw or a slow answer all mean "do not
   *  expand". Human plane only. */
  symbolShape?(token: string, opts?: ShapeOpts): Promise<SymbolShape | null>;
  /** Reply row reservation §3.6, §11.5: how the reply filter relays this
   *  session's terminal. Null (or absent) means no expansion. Human plane
   *  only. */
  sessionRelay?(sessionKey: string): Promise<SessionRelayState | null>;
  /** Reply row reservation §3.8: record a block the proxy expanded (the
   *  head's token, N, and W/F for a v2 head), so the reply filter can lay
   *  out a continuation row whose head never reached the screen. OPTIONAL
   *  and UTILITY-ONLY: absent or failing, the block still expands (its
   *  headless rows paint blank, the old fail-safe). Human plane only. */
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
  /** Confidentiality §6, OpenClaw's history redaction across a relaunch:
   *  the placeholder records an earlier launch's proxy kept for these
   *  tool-call ids (openclaw-redaction.ts). OPTIONAL and UTILITY-ONLY:
   *  absent or failing, a relaunch masks a redacted result whole (an
   *  over-mask, never a leak). Human plane only. */
  forwardedPlaceholders?(ids: string[]): Promise<PlaceholderMapWire[]>;
  /** Record, for results forwarded in clear in an OpenClaw session, where
   *  Mandu's placeholders sat and the text's digest. Tokens, offsets and a
   *  digest only. OPTIONAL and UTILITY-ONLY, human plane only. */
  recordForwardedPlaceholders?(maps: PlaceholderMapWire[]): Promise<void>;
  /**
   * Emit an observability event to the arbiter's privileged event log / dashboard
   * (NEW arbiter op — `{op:"emit", event}` → `{seq}`). BEST-EFFORT and OFF THE
   * SECURITY PATH: the proxy always wraps this so a failed/slow emit can never
   * block or fail a request, and never feeds data back toward T-LLM. The raw
   * untrusted bytes an event may carry go ONLY here (privileged side), never
   * upstream.
   */
  emit(event: ArbiterEvent): Promise<EmitResult>;
}

/** The wrap rule a TUI lays its reply out by (reply-row-reservation.md §17;
 *  reserve-layout.ts LayoutRule). */
export type ReplyLayoutRule = "ink" | "terminal";

/** A `symbolShape` layout: the content width, the head row's width, the
 *  TUI's wrap rule (absent: `ink`), and the terminal column the content area
 *  starts at, which a TAB's stop counts from (§11.2; absent: 0). */
export interface ShapeOpts {
  width: number;
  first: number;
  rule?: ReplyLayoutRule;
  indent?: number;
}

/** The `symbolShape` answer: the value's line count, and with a width its
 *  row count there (§11.5). Never the value. */
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
  /** The agent's TUI wraps its reply by this rule (§17); absent: `ink`. */
  rule?: ReplyLayoutRule;
  updatedAt: number;
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package owned by another sub-agent).
 *
 * The two NEW ops have now LANDED on the real client; their signatures differ
 * slightly from this package's proxy-facing `Arbiter` interface, and the adapter
 * below bridges them:
 *   - real:  handlingPrompt(mode?: string): Promise<string>
 *     proxy: handlingPrompt(args?: {mode?}): Promise<{prompt}>
 *   - real:  recordToolCall(args): Promise<{ok:true, ...}>   (compatible)
 * The two ops are typed OPTIONAL so the adapter can detect an older arbiter build
 * that predates them and FAIL CLOSED rather than silently skip symbolization.
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  classify(req: ClassifyRequest): Promise<ClassifyResult>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  // NEW op: returns the bare prompt string, takes a bare `mode` plus optional
  // tool-battery capabilities (older clients accept and drop the 2nd arg —
  // absent capabilities = full prompt on the arbiter side).
  handlingPrompt?(
    mode?: string,
    capabilities?: HandlingPromptCapabilities,
    sessionKey?: string,
  ): Promise<string>;
  // NEW op: resolves to at least { ok: true }.
  recordToolCall?(args: RecordToolCallArgs): Promise<{ ok: true }>;
  // Session-health op (dashboard.md §4.21): unknown tool names for a session.
  // Optional — an older arbiter yields "none unknown" (utility, not security).
  toolSurface?(names: string[], sessionKey?: string): Promise<string[]>;
  // The per-agent gate surface (arbiter/ipc/client.ts gateSurface(sessionKey)).
  gateSurface?(sessionKey?: string): Promise<unknown>;
  // NEW op (arbiter event-emission wave): emit an observability event → {seq}.
  // Optional so the adapter can degrade GRACEFULLY (NOT fail closed) when a
  // arbiter build predates it — emission is best-effort, off the security path.
  /** The real client returns the bare `seq` (arbiter/ipc/client.ts); an older
   *  bridge returned `{seq}`. The adapter normalizes both to `{seq}`. */
  emit?(event: ArbiterEvent): Promise<EmitResult | number>;
  // NEW op (P3 sensitive-path gate). Optional so the adapter detects an older
  // arbiter build and THROWS — the proxy then fails closed (denied-sentinel).
  fsPathDecision?(req: FsPathDecisionRequest): Promise<FsPathDecision>;
  // NEW op (the upload gate, DesignSync). Optional so the adapter detects an
  // older arbiter build and THROWS: the upload gate then refuses the call.
  fileUploadDecision?(req: FileUploadDecisionRequest): Promise<FileUploadDecision>;
  // NEW op (Phase-0 exec gate). Optional so the adapter detects an older arbiter
  // build and THROWS — the proxy then fails closed (block sentinel).
  execGate?(req: ExecGateRequest): Promise<ExecGateDecision>;
  // NEW op (Plan 8, the session watermark). Optional: an older arbiter simply
  // has no watermark, and the net gate no-ops.
  sessionEgressDecision?(req: SessionEgressRequest): Promise<SessionEgressDecision>;
  // The per-symbol egress gate (long-standing arbiter op; new to THIS client).
  desymbolizationDecision?(req: DesymbolizationRequest): Promise<DesymbolizationDecision>;
  // The shallow resolve (HUMAN PLANE only): the agent-key release reads the
  // value after the gate allows it (agent-sign-in.md §3).
  resolve?(symbol: string): Promise<string | null>;
  // NEW op (Plan 9, the derived on-disk label). Optional for the same reason: an
  // older arbiter has no derived-label store, so the fs-label hook no-ops.
  labelWrittenPath?(req: LabelWrittenPathRequest): Promise<LabelWrittenPathResult>;
  // NEW op (agent-e2e-harness.md §7.1, session-keyed specs). Optional: an older
  // arbiter resolves every session against its process-global spec, which is
  // exactly the pre-binding behavior (fail-closed for foreign tool names).
  setSessionSpec?(args: {
    sessionKey: string;
    spec: string;
    requestedBy?: string;
  }): Promise<{ bound: string; applied: boolean; reason: string }>;
  // NEW op (symbol-twin-shell-blindness.md §4.1 v2): the exec box's leaf-level
  // twin hints for a command. Optional: an older arbiter has no hint store and
  // the note rests on the proxy's own command parse (utility, not security).
  execTwinsFor?(command: string): Promise<{ signature: string; twins: { asTyped: string; abs: string }[]; more?: number }>;
  /** Plan 10 §4.2: the confidentiality taint of the process tree behind a
   *  tool call (matched by callId, else by the command's exec signature), and
   *  the output rule the fold chose. Optional: an arbiter predating plan 10
   *  has no taint to report. A THROW is treated as "tainted, rule secret"
   *  (fail-closed) by the caller. The shape is the REAL client's
   *  (`arbiter/ipc/client.ts callTaint(callId, opts)`): a one-object
   *  signature here once sent `{callId: {…}}` over the wire, the arbiter
   *  answered "Unknown named parameter 'callId'", and every live Bash result
   *  masked fail-closed (2026-09-24; caught by a battery, not a test, because
   *  the e2e bridge re-shaped the call). `proxy-real-client-parity.test.ts`
   *  now pins the production wiring. */
  callTaint?(callId: string, opts?: { command?: string; session?: string; output?: string; unmappedTool?: string; forPoll?: string }): Promise<CallTaintWire>;
  /** Plan 13 D9 follow-up: one object, as arbiter/ipc/client.ts declares it. */
  recordCallCommand?(args: { callId: string; command?: string; sessionKey?: string }): Promise<{ recorded: boolean; reason?: string }>;
  /** One object, as arbiter/ipc/client.ts declares it (the parity test pins it). */
  sessionPathLabel?(args: { path: string; sessionKey: string; reason?: string }): Promise<{ labeled: boolean; path: string | null; level: string | null; reason: string }>;
  /** Plan 13 §4.5.1: positional `(calls, session?)`, as arbiter/ipc/client.ts
   *  declares it (the parity test pins it). */
  agentReceiptTaint?(calls: Array<{ callId: string; tool: string }>, session?: string): Promise<AgentReceiptTaintWire>;
  /** Positional, as arbiter/ipc/client.ts declares it (the parity test pins it). */
  mcpServerTaint?(tool: string, sessionKey?: string): Promise<McpServerTaintWire>;
  scanSecretValues?(text: string): Promise<{ hits: Array<{ symbol: string; level: string; how?: "value" | "line" }> }>;
  /** One object, as arbiter/ipc/client.ts declares it (the parity test pins it). */
  documentText?(args: DocumentTextRequest): Promise<DocumentTextAnswer>;
  /** Plan 15 §3.2: one object, as arbiter/ipc/client.ts declares it. */
  filterPrompt?(args: FilterPromptRequest): Promise<FilterPromptResult>;
  // Reply row reservation (reply-row-reservation.md §3.3, §3.6, §11.5).
  // Optional: an arbiter predating them means no expansion (utility, never
  // security). Both are human-plane ops: called on the HUMAN client only.
  symbolShape?(token: string, opts?: { width?: number; first?: number; rule?: ReplyLayoutRule; indent?: number }): Promise<SymbolShape | null>;
  sessionRelay?(sessionKey: string): Promise<SessionRelayState | null>;
  noteReserveBlock?(args: ReserveBlockNote): Promise<void>;
  // Confidentiality §7.1 across a resume: ids only, human plane only.
  forwardedClear?(ids: string[]): Promise<string[]>;
  forwardedClearSince?(ids: string[], since?: number): Promise<ForwardedClearAnswer>;
  recordForwardedClear?(ids: string[]): Promise<{ recorded: number; skipped: number }>;
  // Confidentiality §6, OpenClaw's redaction across a relaunch: human plane only.
  forwardedPlaceholders?(ids: string[]): Promise<PlaceholderMapWire[]>;
  recordForwardedPlaceholders?(maps: PlaceholderMapWire[]): Promise<{ recorded: number; skipped: number }>;
  close(): void;
}

/** One result's placeholder record (arbiter protocol
 *  ForwardedPlaceholderMapWire): `[offset, token]` pairs over the text this
 *  proxy forwarded, and its SHA-256 over the call id and that text. */
export interface PlaceholderMapWire {
  callId: string;
  digest: string;
  placeholders: Array<[number, string]>;
}

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

/** The `agentReceiptTaint` answer (arbiter protocol AgentReceiptTaintResultWire). */
export interface AgentReceiptTaintWire {
  calls: Array<{ callId: string; level: string | null; files: string[]; apps: string[]; unattributed?: boolean }>;
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
 * (src/server-main.ts), never in tests. If the connected arbiter predates the
 * two new ops, the adapter throws on use — which the proxy treats as a arbiter
 * error and FAILS CLOSED (refuses the request) rather than leaking.
 */
export class ArbiterClientAdapter implements Arbiter {
  /** `human`: a client on the arbiter's human-plane socket
   *  (arbiter-human-plane.md), used for `symbolShape` and `sessionRelay`,
   *  which the data socket refuses (absent → both answer null, and the proxy
   *  does not expand: reply-row-reservation.md §3.3, §5.3, §11.5), and for
   *  `execGate`, `recordCallCommand` and `callTaint`, whose records the
   *  arbiter believes only from a channel the agent's processes cannot reach
   *  (confidentiality plan 13 §3 D9: the call's gate time, the command it
   *  was given, and its binding to the agent's shell). Absent → those go to
   *  the data socket, where the arbiter records no gate time or command and
   *  binds no call: every shell result is then masked while the session
   *  holds a raw read (fail-closed). The network and path gates
   *  (`desymbolizationDecision`, `fsPathDecision`) ride it too: only an ask
   *  from there spends a human's *Allow once* (arbiter-human-plane.md
   *  §10.3); absent, they ask the data socket, where no once is granted. */
  constructor(
    private readonly client: RealArbiterClient,
    private readonly human?: Pick<RealArbiterClient, "symbolShape" | "sessionRelay" | "noteReserveBlock"> & Partial<Pick<RealArbiterClient, "execGate" | "callTaint" | "recordCallCommand" | "agentReceiptTaint" | "emit" | "recordToolCall" | "filterPrompt" | "desymbolizationDecision" | "fsPathDecision" | "fileUploadDecision" | "resolve" | "forwardedClear" | "forwardedClearSince" | "recordForwardedClear" | "forwardedPlaceholders" | "recordForwardedPlaceholders" | "sessionEgressDecision">>,
  ) {}

  /**
   * Agent-sign-in.md §3: the agent's own key for an auth header. The gate and
   * the resolve both ride the HUMAN client, never the data socket (the shallow
   * resolve is refused there, and a decision asked there could not be acted
   * on). No human client, or one without either op ⇒ null: the placeholder
   * stays. A throw propagates (the caller keeps the placeholder).
   */
  async authCredential(req: { symbol: string; destination: string; scheme: "http" | "https"; sessionKey?: string }): Promise<{ value: string | null; reason: string }> {
    const h = this.human;
    if (!h?.desymbolizationDecision || !h.resolve) return { value: null, reason: "no human plane: the key is not put back" };
    const d = await h.desymbolizationDecision({
      symbol: req.symbol, boundary: "network", destination: req.destination, scheme: req.scheme,
      // The value goes into the auth header and nowhere else
      // (auth-substitution.ts): the one position this ask covers.
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

  async toolSurface(names: string[], sessionKey?: string): Promise<{ unknown: string[] }> {
    if (!this.client.toolSurface) return { unknown: [] }; // older arbiter: no drift signal
    return { unknown: await this.client.toolSurface(names, sessionKey) };
  }

  async gateSurface(req: { sessionKey?: string }): Promise<unknown> {
    // Forward the one optional argument POSITIONALLY: the real client takes
    // `gateSurface(sessionKey?)`, not an object (the callTaint lesson, parity
    // test proxy-real-client-parity). Absent op ⇒ throw, and the cache falls
    // back to the union of every agent's table (never less gating).
    if (!this.client.gateSurface) throw new Error("arbiter does not implement gateSurface");
    return this.client.gateSurface(req.sessionKey);
  }

  async handlingPrompt(args?: HandlingPromptArgs): Promise<{ prompt: string }> {
    if (!this.client.handlingPrompt) {
      throw new Error(
        "arbiter does not implement handlingPrompt (op not yet landed) — fail closed",
      );
    }
    // Bridge the real client's bare-string return into the proxy's {prompt}.
    const prompt = await this.client.handlingPrompt(args?.mode, args?.capabilities, args?.sessionKey);
    return { prompt };
  }

  async recordToolCall(args: RecordToolCallArgs): Promise<{ ok: true }> {
    // arbiter-human-plane.md §10.2: believed only from the human socket (the
    // inspect helper's triage reads it); on the data socket it is a claim.
    const via = this.human?.recordToolCall ? this.human : this.client;
    if (!via.recordToolCall) {
      throw new Error(
        "arbiter does not implement recordToolCall (op not yet landed) — fail closed",
      );
    }
    await via.recordToolCall(args);
    return { ok: true };
  }

  async fsPathDecision(req: FsPathDecisionRequest): Promise<FsPathDecision> {
    // arbiter-human-plane.md §10.3: on the human client when there is one
    // (only an ask from there spends a human's Allow once).
    const via = this.human?.fsPathDecision ? this.human : this.client;
    if (!via.fsPathDecision) {
      throw new Error(
        "arbiter does not implement fsPathDecision (op not yet landed) — fail closed",
      );
    }
    return via.fsPathDecision(req);
  }

  async fileUploadDecision(req: FileUploadDecisionRequest): Promise<FileUploadDecision> {
    // On the human client when there is one: the arbiter reads the file only
    // for an ask from there (a data-socket claim never makes it read one, and
    // is answered `fs:upload-unattested`, a refusal), and only an ask from
    // there spends a human's Allow once (arbiter-human-plane.md §10.3).
    const via = this.human?.fileUploadDecision ? this.human : this.client;
    if (!via.fileUploadDecision) {
      throw new Error("arbiter does not implement fileUploadDecision (op not yet landed) — fail closed");
    }
    return via.fileUploadDecision(req);
  }

  async execGate(req: ExecGateRequest): Promise<ExecGateDecision> {
    // Plan 13 D9: on the human client when there is one (the gate time of
    // the call is believed only from there).
    const via = this.human?.execGate ? this.human : this.client;
    if (!via.execGate) {
      throw new Error(
        "arbiter does not implement execGate (op not yet landed) — fail closed",
      );
    }
    return via.execGate(req);
  }

  async sessionEgressDecision(req: SessionEgressRequest): Promise<SessionEgressDecision> {
    // On the human client when there is one (confidentiality.md §4, "The
    // human half"): only an ask from there spends a human's Allow once for a
    // HIGH session's request (arbiter-human-plane.md §10.3); from the data
    // socket an approval is no verdict, and the request stays refused.
    if (this.human?.sessionEgressDecision) return this.human.sessionEgressDecision(req);
    if (!this.client.sessionEgressDecision) {
      // An arbiter predating Plan 8 has NO watermark, so there is nothing to
      // enforce and nothing to fail closed about. Report allow — this is not a
      // fail-open: the op's absence means the session label does not exist, not
      // that we failed to read it.
      return { allow: true, requiresApproval: false, reason: "arbiter predates the session watermark" };
    }
    return this.client.sessionEgressDecision(req);
  }

  async desymbolizationDecision(req: DesymbolizationRequest): Promise<DesymbolizationDecision> {
    // arbiter-human-plane.md §10.3: on the human client when there is one
    // (only an ask from there spends a human's Allow once).
    const via = this.human?.desymbolizationDecision ? this.human : this.client;
    if (!via.desymbolizationDecision) {
      // Unlike the watermark ops there is no "predates it" reading: the symbol
      // exists, so SOMETHING must judge its egress. Throw ⇒ the gate blocks.
      throw new Error("arbiter client has no desymbolizationDecision op");
    }
    return via.desymbolizationDecision(req);
  }

  async labelWrittenPath(req: LabelWrittenPathRequest): Promise<LabelWrittenPathResult> {
    if (!this.client.labelWrittenPath) {
      // An arbiter predating Plan 9 has no derived-label store: the label CANNOT
      // exist, so we did not fail to write it. Report "not labeled" rather than
      // throwing, which the caller would (correctly) treat as unreachable and use
      // to deny an ordinary write.
      return {
        labeled: false, refused: false, level: "public", bindings: [],
        reason: "arbiter predates the derived on-disk label",
      };
    }
    return this.client.labelWrittenPath(req);
  }

  async execTwinsFor(command: string): Promise<{ twins: { asTyped: string; abs: string }[]; more?: number }> {
    // Utility-only: an arbiter predating the hint store simply has no hints.
    if (!this.client.execTwinsFor) return { twins: [] };
    const r = await this.client.execTwinsFor(command);
    return { twins: Array.isArray(r?.twins) ? r.twins : [], ...(typeof r?.more === "number" ? { more: r.more } : {}) };
  }

  async emit(event: ArbiterEvent): Promise<EmitResult> {
    // Emission is BEST-EFFORT and off the security path. Unlike handlingPrompt /
    // recordToolCall, a arbiter that predates `emit` must NOT fail the request —
    // we degrade to a no-op (seq:-1). The proxy additionally wraps every emit in
    // its own try/catch, so this never throws toward the request path either.
    // arbiter-human-plane.md §10.2: on the human client when there is one,
    // where the event is believed; a failure there, or none, sends it on the
    // data socket, where the arbiter stores it as a claim.
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

  async mcpServerTaint(req: { tool: string; sessionKey?: string }): Promise<McpServerTaintWire> {
    // An arbiter predating plan 10 §11.13 maps no server: each proxy keeps its older rule.
    if (!this.client.mcpServerTaint) return { verdict: "unmapped", candidates: 0, level: null, files: [], apps: [] };
    return this.client.mcpServerTaint(req.tool, req.sessionKey);
  }

  async callTaint(req: { callId: string; command?: string; sessionKey?: string; output?: string; unmappedTool?: string; forPoll?: string }): Promise<CallTaintWire> {
    // Plan 13 D9: on the human client when there is one (only an ask from
    // there binds the call to the agent's shell for it).
    const via = this.human?.callTaint ? this.human : this.client;
    if (!via.callTaint) {
      // An arbiter predating plan 10 has no process taint: nothing to render.
      return { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
    }
    return via.callTaint(req.callId, { ...(req.command ? { command: req.command } : {}), ...(req.sessionKey ? { session: req.sessionKey } : {}), ...(req.output ? { output: req.output } : {}), ...(req.unmappedTool ? { unmappedTool: req.unmappedTool } : {}), ...(req.forPoll ? { forPoll: req.forPoll } : {}) });
  }

  async recordCallCommand(req: { callId: string; command?: string; sessionKey?: string }): Promise<{ recorded: boolean }> {
    // Plan 13 D9 follow-up: on the human client when there is one (the data
    // socket records nothing). An arbiter predating the op records nothing:
    // the call then binds by execGate's record alone (fail-closed on a miss).
    const via = this.human?.recordCallCommand ? this.human : this.client;
    if (!via.recordCallCommand) return { recorded: false };
    const r = await via.recordCallCommand({ callId: req.callId, ...(req.command !== undefined ? { command: req.command } : {}), ...(req.sessionKey ? { sessionKey: req.sessionKey } : {}) });
    return { recorded: r.recorded === true };
  }

  async sessionPathLabel(req: { path: string; sessionKey: string; reason?: string }): Promise<{ labeled: boolean; path: string | null }> {
    // Raise-only, so the data socket answers it. An arbiter predating the op:
    // the caller masks the result that names the path (fail-closed).
    if (!this.client.sessionPathLabel) throw new Error("the arbiter has no sessionPathLabel op");
    const r = await this.client.sessionPathLabel({ path: req.path, sessionKey: req.sessionKey, ...(req.reason ? { reason: req.reason } : {}) });
    return { labeled: r.labeled === true, path: typeof r.path === "string" ? r.path : null };
  }

  async agentReceiptTaint(req: { calls: Array<{ callId: string; tool: string }>; sessionKey?: string }): Promise<AgentReceiptTaintWire> {
    // Plan 13 §4.5.1: on the human client when there is one (only its first
    // ask ends a call's window; from the data socket the arbiter only
    // reads, with `now` as the end, which can only mask more). An arbiter
    // predating the op masks nothing by this leg.
    const via = this.human?.agentReceiptTaint ? this.human : this.client;
    if (!via.agentReceiptTaint) return { calls: req.calls.map((c) => ({ callId: c.callId, level: null, files: [], apps: [] })) };
    return via.agentReceiptTaint(req.calls, req.sessionKey);
  }

  async symbolShape(token: string, opts?: ShapeOpts): Promise<SymbolShape | null> {
    // Utility-only: without the human plane (or an arbiter predating the op)
    // there is no shape to give. Never the data socket: it refuses the op.
    if (!this.human?.symbolShape) return null;
    // The real client's shape: (token, {width, first, rule?, indent?}),
    // positional token. `rule` and `indent` only when given: an arbiter
    // predating them reads the request without them.
    const r = opts
      ? await this.human.symbolShape(token, {
          width: opts.width, first: opts.first, ...(opts.rule !== undefined ? { rule: opts.rule } : {}),
          ...(opts.indent !== undefined ? { indent: opts.indent } : {}),
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

  async forwardedPlaceholders(ids: string[]): Promise<PlaceholderMapWire[]> {
    // Utility-only, human plane only (confidentiality.md §6, OpenClaw's
    // redaction across a relaunch): without the human client, or an arbiter
    // predating the op, nothing is known (a redacted result is masked whole).
    if (!this.human?.forwardedPlaceholders) return [];
    return this.human.forwardedPlaceholders(ids);
  }

  async recordForwardedPlaceholders(maps: PlaceholderMapWire[]): Promise<void> {
    // Utility-only, human plane only: without it the restore lasts this
    // launch. Positional array, as arbiter/ipc/client.ts takes it.
    if (!this.human?.recordForwardedPlaceholders) return;
    await this.human.recordForwardedPlaceholders(maps);
  }

  async scanSecretValues(text: string): Promise<{ hits: Array<{ symbol: string; level: string; how?: "value" | "line" }> }> {
    if (!this.client.scanSecretValues) throw new Error("arbiter does not implement scanSecretValues — the value backstop cannot run");
    return this.client.scanSecretValues(text);
  }

  async documentText(req: DocumentTextRequest): Promise<DocumentTextAnswer> {
    if (!this.client.documentText) return { text: null, reason: "the arbiter does not read document blocks" };
    return this.client.documentText(req);
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
