/**
 * event-model — the canonical Mandu observability event schema.
 *
 * Mandu-new (NO reference origin). This is the unified `ManduEvent` record
 * specified in docs/design/ui/dashboard.md §2. It replaces the reference
 * dashboard's three parallel JSONL families (conversation + audit + llm-requests)
 * with ONE typed record whose three load-bearing additions are:
 *   - `view`     (§2.1) — first-class AgentView | HumanView | Quarantine lane.
 *   - `DualRepr` (§2.2) — every input/output carried in both the symbolized form
 *                         T-LLM saw and the original form HumanView saw.
 *   - `invariant`(§2.4) — the per-event flag the §9 oracle computes at emit time
 *                         and the dashboard merely renders.
 *
 * `SymbolRef` (§2.3) mirrors arbiter/symbol-table `SymbolEntry`
 * (tool/field/origin/session_key/call_id + derived_from/line_range). Field names
 * here are camelCased for the JS/TS frontend; the arbiter→event mapping is the
 * seam where snake_case `SymbolEntry` is projected onto `SymbolRef` (see
 * `fromSymbolEntry`).
 */

// ── The view dimension (§2.1) — the lane each event renders in ────────────────

export type View =
  | "AgentView" //   What T-LLM sees: symbolized context, AgentFS reads, AgentShell.
  | "HumanView" //   Original data: on-disk files, desymbolized egress, HumanShell.
  | "Quarantine"; // The U-LLM lane: untrusted text processed in isolation, re-symbolized.

export const VIEWS: readonly View[] = ["AgentView", "HumanView", "Quarantine"] as const;

// ── Symbol provenance (§2.3) — mirrors arbiter SymbolEntry ─────────────────────

export interface SymbolRef {
  /** "$MDU:web_fetch[a1b2].text" */
  name: string;
  /** emitting tool / origin chokepoint, e.g. "web_fetch" */
  tool: string;
  /** schema field path, e.g. "text"; null if none */
  field: string | null;
  /** URL / channel id / dir path the value came from; null if N/A */
  origin: string | null;
  /** resolved original (privileged reveal); null if not resolved/N/A */
  value: string | null;
  /** re-symbolization lineage (U-LLM output / git blame parent symbol) */
  derivedFrom?: string;
  /** FS provenance for blame-based re-symbolization, e.g. "0:29" */
  lineRange?: string;
  /** Confidentiality level (docs/design/confidentiality/confidentiality.md §2): "public" |
   *  "any-model" | "local-model" | "no-model". ABSENT ⇒ the axis is off, or the
   *  datum is public — never invent a level. PRESENTATION ONLY: the arbiter's
   *  symbol table decides; this exists so the dashboard and the §12 oracle can
   *  SEE what it decided. */
  confidentiality?: string;
}

// ── The two-representation model (§2.2) ───────────────────────────────────────

export interface DualRepr {
  /** What T-LLM / AgentView saw. Untrusted spans are $MDU:* here. */
  symbolized: string;
  /** What HumanView / the real world saw. null if not desymbolized for this
   *  event (an AgentView-only read whose original never left the boundary).
   *  The privileged dashboard may still resolve on demand → rendered "(revealed)". */
  original: string | null;
  /** True iff symbolized !== original, i.e. symbolization actually occurred.
   *  Drives side-by-side vs collapsed rendering. */
  differs: boolean;
  /** Symbols referenced in `symbolized`, with provenance. */
  symbols: SymbolRef[];
  /** Set only by the signed-out projection (view-model/redact.ts), which
   *  leaves `original` out: the `$MDU:` placeholders `original` held as
   *  written (names only, never a value), so a page can still tell a
   *  placeholder the tool merely echoed from one it kept from the AI. */
  originalTokens?: string[];
}

// ── Event kinds (§2.4) ────────────────────────────────────────────────────────

export type EventKind =
  // Track A — model-API proxy
  | "tllm_call" //       privileged model request+response (the agent's brain)
  | "ullm_call" //       quarantined model call (inspect_symbol / transparent U-LLM)
  | "tool_use" //        a tool-call decision parsed from the T-LLM response
  | "tool_result" //     a tool result re-entering context (ingress into T-LLM)
  // Arbiter — policy + symbol table
  | "classify" //        data trust policy: TRUSTED/UNTRUSTED decision on ingress
  | "symbolize" //       untrusted span → $MDU:*
  | "desymbolize" //     $MDU:* → original on egress
  | "egress_request" //  data usage policy: a desymbolization needing approval
  | "egress_decision" // approve/deny outcome for an egress_request
  | "path_rewrite" //    P2 ViewMap: HumanView↔AgentView path spelling on the model wire
  // Track B / M3 — OS interceptors
  | "fs_action" //       openat/read/write routed to AgentFS or HumanFS
  | "net_action" //      connect/HTTP routed ingress(symbolize)/egress(desymbolize)
  | "exec_action" //     execve routed to AgentShell or HumanShell
  | "browser_action" //  the DevTools relay (cdp-relay events.ts): a read it masked
  //                    or withheld, a placeholder typed (released / refused), a
  //                    command it stopped; names only (devtools-relay.md §5.1)
  // Arbiter-admin audit stream (policy-surface.md §9.6)
  | "approval_resolved" // a human approve/deny landed on an approval-queue entry —
  //                    emitted into the reserved `arbiter-admin` session (verdicts
  //                    are arbiter-global, so they get the arbiter's own stream)
  | "approval_consumed" // a ONCE-scoped verdict was spent by its one satisfying
  //                    decision (the standing-verdict twin of approval_resolved;
  //                    same arbiter-admin stream — a single-use grant's uses are
  //                    each individually visible, unlike standing-verdict reuse)
  | "posture_change" // the arbiter's egress posture was tightened/relaxed (SIEM
  //                    -triggered lockdown, siem-integration.md §4.3 scenario D) —
  //                    also an arbiter-global event in the `arbiter-admin` stream
  | "config_change" // a boot-time protection axis (integrity/confidentiality) was
  //                    reconfigured via the Protection drawer (dashboard.md §4.19 ②)
  //                    — emitted by the DASHBOARD (the arbiter's emit op is opaque)
  //                    into the same `arbiter-admin` stream, best-effort. Carries
  //                    the top-level scalars axis/from/to/requestedBy the SIEM
  //                    rules key on (a config act is a governance signal: turning
  //                    protection OFF must leave the same who/when trail a posture
  //                    change does)
  | "policy_model_call" // one model run for policy suggestions, names only
  //                    or a local model reading documents
  //                    (confidentiality-plan-14 §14.5, §14.11): the arbiter's, in the
  //                    arbiter-admin stream; COUNTS ONLY (tier, endpoint name,
  //                    location, placement, names, bytes, requests, duration,
  //                    rules kept / dropped / filed, failed requests), never a
  //                    name or an answer (`policyModelCall`)
  // Session HEALTH stream (dashboard.md §4.21, 2026-09-05): the launcher, the
  // reply-filter and the proxies each say what posture the session ACTUALLY
  // runs at, so a session that boots thinner than the product default — a
  // dropped rung, a passthrough relay, an unknown tool surface, a tool that
  // cannot execute — is visible per session instead of only in a CI oracle.
  | "launch_posture" // the launcher's rung banners at launch: which default-on
  //                    rungs came up LIVE and which were DROPPED/degraded (+ why)
  | "relay_mode" //     the reply-filter's mode decision for the human terminal:
  //                    pty relay / pipe / PASSTHROUGH (symbols would stay opaque);
  //                    again with `resolveFailure` (a reason) when its lookups
  //                    start failing, and plain once they answer again
  | "client_info" //    the agent CLI's user-agent + version as seen on the first
  //                    model request (the "which Claude Code is this" signal)
  | "tool_surface" //   the tool battery the agent advertised on its first request
  //                    and which names the active inbound spec does NOT know
  //                    (their outputs fail closed → symbolized → utility loss)
  | "session_exit" //   the agent exited: code + wall time
  | "session_level" //  the arbiter raised the session's confidentiality
  //                    high-watermark (a secret read into the model's context:
  //                    declassify_symbol, confidentiality.md §4): from → to, the
  //                    symbol's NAME and the session's bindings (`sessionLevel`),
  //                    never content. Off the security path, best-effort
  // The prompt filter (confidentiality-plan-15 §8): the model proxies report
  // what the filters found in one segment of the user-role text and what
  // they did (`promptFilter`): symbols, categories and counts, never a value.
  | "prompt_filter"
  // Test harness — the e2e SECURITY/UTILITY assertion verdict for the session
  | "assertion" //       one per e2e session: the security + utility check results
  | "workspace_seed" // the files the e2e harness planted in the workspace BEFORE
  //                    the run (raw content) — the setup-banner's honest record of
  //                    the initial disk state, surviving throwaway-workspace deletion
  | "workspace_final"; // the FINAL file trees of both views (capped content) at
  //                     scenario end — the seed's twin, letting the Files tab render
  //                     a session whose workspace dir is gone (CI docker / rmSync'd tmp)

export const EVENT_KINDS: readonly EventKind[] = [
  "tllm_call", "ullm_call", "tool_use", "tool_result",
  "classify", "symbolize", "desymbolize", "egress_request", "egress_decision",
  "path_rewrite",
  "fs_action", "net_action", "exec_action", "browser_action",
  "approval_resolved", "approval_consumed", "posture_change", "config_change", "policy_model_call",
  "launch_posture", "relay_mode", "client_info", "tool_surface", "session_exit", "session_level",
  "prompt_filter",
  "assertion", "workspace_seed", "workspace_final",
] as const;

export type Boundary = "model_context" | "network" | "filesystem" | "shell";

export type Emitter =
  | "anthropic-proxy" //   Track A — Claude Code (Anthropic Messages API)
  | "openai-proxy" //   Track A — Codex CLI (OpenAI Responses API)
  | "arbiter" //        symbolize/desymbolize/classify/egress
  | "fs-supervisor" // Track B
  | "net-supervisor"
  | "exec-supervisor" // M3
  | "inspect-mcp" //    the cooperative U-LLM path (`ullm_call` events)
  | "reply-filter" //   user-reply egress (`desymbolize` events)
  | "fs-sync" //        FS view-sync symbol BIRTHS (`symbolize` events, symbol-lineage.md G1)
  | "dashboard" //      the Protection drawer's config acts (`config_change` events —
  //                    the dashboard is the actor that edits config.toml, so it is
  //                    the honest emitter; the arbiter only stores the event)
  | "launcher" //       the per-session launcher (`launch_posture` / `session_exit`)
  | "cdp-relay" //      the DevTools relay between a browser agent and Chrome (`browser_action`)
  | "test-harness"; //  the e2e suite that emits the per-session `assertion` verdict

export interface EventPolicy {
  trust?: "TRUSTED" | "UNTRUSTED";
  category?: string | null;
  reason?: string;
  usage?: "allow" | "deny" | "needs_approval";
  shell?: "AgentShell" | "HumanShell";
  /** Decision provenance (docs/design/ui/policy-surface.md §9.3): which standing
   *  rule (`fs:sensitive-path`), human verdict (`verdict:egr-2`), or
   *  fail-closed default decided this. Mirrors arbiter/policy/rule-ref.ts;
   *  the Policy panel joins on `id`. Absent on pre-provenance events. */
  ruleRef?: { source: "rule" | "verdict" | "fail-closed"; id: string };
  /** The approval-queue row a queued deny created/bumped (`egr-<n>`) — the
   *  Pending tab highlights the rows the loaded session touched
   *  (policy-surface.md §9.5). Absent on pre-provenance events and on
   *  verdict short-circuits (their join is `ruleRef: verdict:<id>`). */
  approvalId?: string;
  /** The OTHER half of the 2×3 label (confidentiality.md §2). Absent ⇒ the
   *  confidentiality axis is off, or the datum is public. A TRUSTED trust with
   *  a secret level is the normal shape for a credential file: symbolized by
   *  PROVENANCE, not by distrust. */
  confidentiality?: string;
}

export interface EventInvariant {
  /** True iff this event would put UN-symbolized UNTRUSTED data into T-LLM's
   *  context. MUST be false for every event in a healthy session. The §9 oracle
   *  asserts ∀ events: !violatedInvariant. The UI flares red on any true value. */
  violatedInvariant: boolean;
  /** What leaked + where (for the drill-down). */
  detail?: string;
}

export interface EventModel {
  id: string;
  inputTokens?: number;
  outputTokens?: number;
  /** The provider's id for this response (`msg_…` from the Messages API,
   *  `resp_…` from the Responses API), set by the model proxies on a
   *  `tllm_call` whose response carried one. The agent's own transcript
   *  keeps the same id, so `mandu scan` joins on it to tell a past session
   *  under Mandu exactly (confidentiality-plan-17 §3 item 6). Not a secret;
   *  nothing else from the response is recorded with it. */
  responseId?: string;
  /** The agent's own id of its session as the request carried it
   *  (OpenCode's `X-Session-Id` / `x-opencode-session-id`, `ses_…`), set by
   *  the anthropic-proxy on a `tllm_call`: OpenCode keeps no response id on
   *  most wires but keeps this as the session's id, so `mandu scan` joins
   *  on it (confidentiality-plan-17 §3 item 6). An opaque id; not a secret. */
  agentSessionId?: string;
}

// ── e2e SECURITY / UTILITY / FIDELITY assertions (dashboard.md §4.13) ──────────

/**
 * PROVENANCE (CONTRIBUTING.md reuse policy): the category (blocking security vs
 * non-blocking utility) assertion model + the `pass/fail/warn/skip` status set
 * are lifted from the reference DualView e2e harness
 *   DualView (adfi-openclaw) tests/lib/assertions.ts (AssertionResult,
 *   the `category: "correctness" | "utility"` split)
 * and its dashboard's assertion panel
 *   https://github.com/compsec-snu/dualview/blob/main/dashboard/api/routes.ts (the parsed
 *   {status,label,reason,category,tool,assert} result shape).
 * Adapted for Mandu: the reference's blocking category is `correctness`; here it
 * is `security` (the information-flow invariant — untrusted data reaches
 * T-LLM only symbolized, raw never leaks, trusted rides verbatim), the exact
 * property the one invariant serves. `utility` is unchanged in spirit: the benign
 * task still completed despite the defense. `fidelity` is Mandu-new (2026-07-11,
 * split out of utility): the dashboard's render equals what happened — the
 * history-fidelity oracle (trace cards ≡ Claude Code's own transcript) and the
 * stale-daemon alarm, i.e. observability truthfulness rather than task success.
 * `warned` is Mandu-new (2026-10-17): the human was TOLD that a place the data
 * may not go asked for it (an Approvals card naming the place, or the agent
 * saying so on the screen). Neither security (the data may be kept without a
 * word) nor utility (the task is done either way): the drill head-to-head's
 * third measure (docs/testing/drill-runner.md §7.5).
 */
export type AssertionCategory = "security" | "utility" | "fidelity" | "warned";

/**
 * Which security property a `security` check proves (2026-07-16, §4.13) — the
 * attacker-gain axis: what the attacker would gain if the check failed.
 *   `integrity`       — untrusted data steered the agent: symbolization into
 *                       T-LLM, trust-taint on derivation (re-symbolization),
 *                       dual-view FS/routing, U-LLM quarantine, exec/fs gates,
 *                       sabotage compliance.
 *   `confidentiality` — secret data leaked: secrecy labels + tainting
 *                       (no-model / local-model / any-model, session LOW→HIGH,
 *                       derived labels, cross-session), the net exfiltration
 *                       gate, the wire canary.
 * Only meaningful on `category: "security"` checks; absent on utility/fidelity
 * checks and on legacy persisted events (which render as an unsplit Security
 * group). Grouping is by property at risk, NOT mechanism — label-lineage /
 * tainting checks distribute across both by which label system they track.
 */
export type SecurityAspect = "integrity" | "confidentiality";

/** pass = satisfied; fail = violated + BLOCKING (fails the test); warn = violated
 *  but NON-BLOCKING (a soft check, advisory); skip = not applicable to this
 *  scenario (its precondition/flag was absent). */
export type AssertionStatus = "pass" | "fail" | "warn" | "skip";

/** One evaluated e2e check. Carried in an `assertion` event's `assertions[]`. */
export interface AssertionCheck {
  /** Stable short label, e.g. "raw-injection-absent". */
  label: string;
  /** One-line description of the property the check proves. */
  description?: string;
  /** security = the blocking security invariant; utility = the benign task;
   *  fidelity = the rendered trace matches what the client itself recorded;
   *  warned = the human was told a place the data may not go asked for it. */
  category: AssertionCategory;
  /** The security sub-property (integrity | confidentiality) — set on every
   *  security check the harness emits today, absent elsewhere. */
  aspect?: SecurityAspect;
  status: AssertionStatus;
  /** The evidence — why it passed/failed/was skipped. */
  reason: string;
  /** The tool this check concerns (Read/Bash/WebFetch/…), for context. */
  tool?: string;
  /** The assertion primitive used (symbol_reaches_model, raw_absent, …). */
  assert?: string;
}

/**
 * The `assert` keys of the HISTORY-FIDELITY oracle (the live claude-e2e suite's
 * "dashboard render ≡ Claude Code's own transcript" block —
 * tests/lib/claude-history.ts historyFidelityChecks) plus the
 * render self-check it runs alongside (renderLintChecks over
 * view-model/render-lint.ts — one shared `render_lint` key). The
 * sidebar derives a per-session fidelity verdict by filtering the session's
 * `assertion` event on this set (event-source/registry.ts assertionVerdicts). KEEP IN
 * SYNC with claude-history.ts — pinned by a test there
 * (tests/stack/claude-history.test.ts).
 */
export const HISTORY_FIDELITY_ASSERTS: ReadonlySet<string> = new Set([
  "history_prompts", "no_bogus_input", "final_reply_matches", "history_tools",
  "render_lint",
]);

// ── Seeded workspace files (§4.11) — the harness-prepared initial disk state ───

/**
 * One file the e2e harness wrote into the workspace BEFORE spawning the agent.
 * Carried on a `workspace_seed` event so the dashboard can show the RAW prepared
 * content truthfully (event-sourced) even after a throwaway workspace is deleted
 * at teardown. `content` is the raw original — a HumanView fact, same privilege
 * posture as DualRepr.original: the event store is a human-facing surface, never
 * T-LLM context.
 */
export interface SeededFile {
  /** Workspace-relative path (e.g. "notes.md"). */
  path: string;
  /** The raw file content as written by the harness. */
  content: string;
  /** True iff the harness planted an injection payload in this file. */
  poisoned: boolean;
  /** Set by the signed-out projection (view-model/redact.ts): `content` was
   *  left out because the viewer has no admin session (dashboard.md §6). */
  withheld?: true;
  /** The EFFECTIVE confidentiality level of this file at run start (catalog +
   *  any explicit label the scenario applied), for the confidentiality (CONF-*)
   *  scenarios. Omitted for non-conf runs (the axis is off, every file public).
   *  This is the "which files are secret, and why" surface — a `.env` shows
   *  `no-model` from the zero-config catalog, a labeled contract shows
   *  `any-model` with its source. */
  confidentiality?: {
    level: "public" | "any-model" | "local-model" | "no-model";
    /** How the level was decided: "catalog" (the zero-config default) or
     *  "label:<via>" (an explicit human label the scenario applied). */
    source: string;
    /** Bound egress destinations carried by the label, if any (§3.2). */
    bindings?: string[];
  };
}

// ── Final workspace files (§4.12) — the harness-recorded end-of-run disk state ─

/**
 * One file of a view's FINAL tree at scenario end, recorded by the e2e harness
 * on a `workspace_final` event. Field names deliberately mirror the /api/fs
 * `FsFile` response (fs-view.ts) so the route can serve an event-sourced
 * snapshot nearly verbatim when the git-sourced one is unavailable. Same
 * privilege posture as SeededFile.content / DualRepr.original: the event store
 * is a human-facing surface, never T-LLM context.
 */
export interface FinalFile {
  /** Workspace-relative path (`/`-separated, like git ls-tree). */
  path: string;
  /** UTF-8 content, possibly cut at the capture cap; null for binary files,
   *  files over the read ceiling, or files past the per-view content budget. */
  content: string | null;
  /** Full on-disk byte size (even when content is cut or absent). */
  size: number;
  /** True when the shipped content is shorter than the file (or unread). */
  truncated: boolean;
  /** True when the file looks binary (NUL in the first 8 KiB) — no content. */
  binary: boolean;
  /** Set by the signed-out projection (view-model/redact.ts): a HumanView
   *  file's `content` was left out (no admin session, dashboard.md §6). */
  withheld?: true;
}

/**
 * One view's final tree on a `workspace_final` event. Grouped per view (not a
 * flat list) so root and list-truncation are per-view facts, matching how
 * /api/fs serves one view per request.
 */
export interface FinalWorkspaceView {
  /** AgentView = the symbolized worktree; HumanView = the raw user workspace. */
  view: "AgentView" | "HumanView";
  /** The absolute captured root (display only — the UI's explorer header). */
  root: string;
  /** The view's files, sorted by path. */
  files: FinalFile[];
  /** True iff the FILE LIST is incomplete (the capture's file-count cap hit) —
   *  per-file content cuts are flagged on each FinalFile instead. */
  truncated: boolean;
}

// ── Full model-call input (§4.3.3) — complete, source-tagged, on-demand ────────

/**
 * One block of a model call's COMPLETE, untruncated input, tagged by source so
 * the UI can reveal the full prompt and HIGHLIGHT what Mandu injected:
 *   - "mandu"      = the injected handling prompt (T-LLM) / quarantine prompt (U-LLM).
 *   - "agent"        = the agent's own system prompt / blocks.
 *   - "conversation" = the messages / inspected data.
 * `text` is the FULL SYMBOLIZED text — no system/prompt cap, and never raw
 * untrusted bytes (it captures what the model actually received).
 */
export interface FullInputBlock {
  role: "system" | "user" | "assistant" | "tool_result";
  source: "mandu" | "agent" | "conversation";
  text: string;
  label?: string;
}

/** The complete, untruncated structured input to a model call. */
export interface FullInput {
  blocks: FullInputBlock[];
}

// ── tllm_call structural shape (§4.2c side-call detection) ────────────────────

/**
 * Structural request metadata on a `tllm_call` — what the model proxy KNOWS
 * about the call it forwarded, recorded so the dashboard can separate the agent
 * CONVERSATION loop from harness side calls (title generation, the startup
 * quota probe, typeahead suggestion, away-recap, the WebFetch summarizer)
 * STRUCTURALLY instead of by string heuristics over prompt text. The agent
 * conversation loop always carries the agent's tool battery; every known side
 * call sends none — so `toolCount === 0` is a side call regardless of what a
 * future Claude Code release makes its prompt say. String heuristics remain the
 * fallback for events that predate this field.
 */
export interface TllmCallShape {
  /** Number of entries in the request's `tools` array (0 when absent). */
  toolCount: number;
  /** The request's `max_tokens`, if present (the quota probe sends 1). */
  maxTokens: number | null;
  /** Count of user-role messages (a stateless one-shot side call has 1). */
  userMessages: number;
}

// ── path_rewrite detail (fs-sync.md §1.3 P2) ───────────────────────────

/**
 * Kind-specific detail on a `path_rewrite` event: one ViewMap application on
 * the model wire. Both spellings are carried so the UI renders the translation
 * without string-scraping:
 *   - `human` — the HumanView spelling (what T-LLM speaks on the model wire).
 *   - `agent` — the AgentView spelling (what the agent process executes on).
 * `direction`: "forward" = model→agent (response tool_use args, human→agent);
 * "reverse" = agent→model (request tool_result content / echoed tool_use args,
 * agent→human). Mirrors anthropic-proxy events.ts `PathRewriteDetail`.
 */
export interface PathRewriteDetail {
  direction: "forward" | "reverse";
  tool: string | null;
  /** Rewritten typed field (file_path/path/…), "command" (Bash text),
   *  "content" (tool_result free text) or "text" (conversation free text) —
   *  the latter two reported at root-pair granularity. */
  field: string | null;
  human: string;
  agent: string;
}

/**
 * How long each named step of a launch took, on its `launch_posture` and
 * `session_exit` events (runtime-instances.md §14.11). Mirrors the
 * launcher's `LaunchTimings` (launcher/src/launch-timings.ts): `steps` in
 * the order they started, a dotted name a part of the step before the dot;
 * `totalMs` from the launcher's process start (or its main() for an
 * in-process launch) to the event. Since 2026-10-22 a top-level step also
 * carries its cost (`cpuMs`: the launcher's CPU time, `git`: the git calls
 * it started, `sandboxes`: the sandboxes made for them), and a whole
 * record its `cost`; an older launcher's record has neither.
 */
export interface LaunchTimingsDetail {
  v: 1;
  totalMs: number;
  steps: Array<{ step: string; ms: number; cpuMs?: number; git?: number; sandboxes?: number }>;
  cost?: { cpuMs?: number; git?: number; sandboxes?: number };
}

/**
 * Kind-specific detail on a `prompt_filter` event (confidentiality-plan-15 §8):
 * what the prompt filter did to ONE segment of a request's user-role text.
 * Offsets into the segment, categories, actions and symbols only: NEVER a
 * value and never the segment's text (a skipped registered value is counted,
 * not named). Mirrors the proxies' `PromptFilterDetail`
 * (interceptors/{anthropic,openai}-proxy/src/events.ts).
 */
export interface PromptFilterDetail {
  /** Whose segmenter cut the text: claude-code, codex, openclaw, opencode, generic. */
  agent: string;
  segmentId: string;
  /** Who wrote the segment (§3.1). */
  origin: "human" | "harness" | "side-call";
  /** `rewrite`: the model read the text with the spans replaced; `block`:
   *  the request was refused and nothing was sent (plan 15 §7). */
  action: "pass" | "rewrite" | "block";
  findings: Array<{
    filterId: string;
    category: string;
    action: string;
    symbol?: string;
    how?: string;
    start: number;
    end: number;
    /** Phase 3 (plan 15 §7): the span's opaque reference (a "let it
     *  through" names it, with the session and `turn`). */
    ref?: string;
    /** Phase 3: a human verdict let the span through as written. */
    let?: "once" | "session";
    /** Phase 3: an `ask` finding's hold. */
    hold?: { state: string; approvalId?: string };
    /** The arbiter's word, copied by the proxy (plan 15 §12, 2026-10-04): a
     *  locked administrator's `ask` row covers the category, so this finding is
     *  let through (or answered) for its message only, never for the session. */
    onceOnly?: true;
  }>;
  /** Phase 3: the message's opaque reference (a "let it through, once"). */
  turn?: string;
  /** Registered values the prompt floor let through (human segments). */
  skipped: number;
  /** False with the confidentiality axis OFF: the findings were logged only. */
  enforcing: boolean;
  digest: { policy: string; packs: string };
}

// ── The canonical event (§2.4) ────────────────────────────────────────────────

export interface ManduEvent {
  // Identity & ordering
  id: string; //            stable, globally unique (ULID — sorts by time)
  sessionId: string; //     Mandu scope id (launcher MANDU_SCOPE_ID)
  turn: number; //          T-LLM request index within the session
  ts: string; //            ISO 8601 wall clock
  seq: number; //           monotonic per-session emit counter (causal tiebreak)
  callId: string | null; // correlates tool_use → fs/net/exec → tool_result
  parentId: string | null; // causal parent (e.g. a fs_action's originating tool_use)

  // Classification
  kind: EventKind;
  view: View; //            AgentView | HumanView | Quarantine (the lane)
  boundary: Boundary;
  emitter: Emitter;
  /** Set by the ARBITER (never taken from the caller) when the event arrived
   *  on a channel the agent's programs reach: the data socket, or the human
   *  socket while a launch with no wall around it is live
   *  (arbiter-human-plane.md §10.2). A CLAIM: its `emitter` and every field
   *  are the sender's word. Shown as such; no dashboard decision reads it
   *  (`believedEvents`). Absent = believed. */
  claimed?: true;

  // Payload, in both representations
  input: DualRepr | null; //  request/argv/path/body the action consumed
  output: DualRepr | null; // response/stdout/file content the action produced

  // Policy decision attached to this event
  policy?: EventPolicy;

  // The invariant flag (the whole point)
  invariant: EventInvariant;

  // Optional model metadata (tllm_call / ullm_call)
  model?: EventModel;

  /** Complete, untruncated input to a model call (tllm_call/ullm_call), each block
   *  tagged by source so the UI can reveal the full prompt + highlight injections.
   *  Optional — only the model-call emitters set it. */
  fullInput?: FullInput;

  /** Which model endpoint served a quarantined call (`ullm_call`, confidentiality
   *  plan 11 D5/D6): the declared `models:` entry's name and whether it is the
   *  user's own model (`local`) or an outside one. The default helper is
   *  `{ name: "default", location: "external" }`. Absent on inspect-mcp builds
   *  predating plan 11; the trace then renders as before. */
  endpoint?: { name: string; location: "local" | "external"; placement?: "host" | "network"; plainHttp?: true };

  /** Batch id: sessions created by one run (e.g. a single "Run e2e" click) share
   *  this so the dashboard sidebar can group them. Rides the `x-mandu-batch-id`
   *  header exactly the way `sessionId` rides `x-mandu-session-id`. Absent for
   *  un-batched traffic (those sessions fall into the sidebar's "Ungrouped" batch).
   *  `coerceEvent` preserves it verbatim (spread), so the arbiter needs no change. */
  batchId?: string;

  /** TENANT (policy-surface.md §2.7): `"live"` — a human's real agent
   *  run — or `"test"` — an e2e suite, a harness, a dev rig. Stamped by whoever
   *  minted the session (the launcher via `x-mandu-tenant` / MANDU_TENANT,
   *  the harness on its own events) or by an explicitly tenanted arbiter on
   *  persist. The dashboard classifies sessions by this stamp FIRST and falls
   *  back to the session-id prefix only for unstamped, pre-tenancy sessions.
   *  Orthogonal to `origin` (WHO ran a test) and `runtime` (WHERE). */
  tenant?: "live" | "test";

  /** Execution runtime the e2e harness ran under: `"docker"` when the suite ran
   *  inside the containerized rig (packaging/docker/), `"host"` on the dev box directly.
   *  Set by the e2e harness on the events it emits (from MANDU_E2E_RUNTIME) so
   *  the sidebar can badge a session/batch docker-vs-host; the container writes
   *  into the host arbiter's shared event dir, so this tag is the only distinguisher.
   *  `coerceEvent` preserves it verbatim (spread), so the arbiter needs no change. */
  runtime?: "docker" | "host";

  /** WHO started the e2e run: `"ci"` = a GitLab pipeline job, `"local"` = a human
   *  on the dev box. Set by the e2e harness (from MANDU_E2E_ORIGIN, or GitLab's
   *  own $CI) so the sidebar can badge a batch as CI.
   *
   *  Deliberately ORTHOGONAL to `runtime`, not a third value of it: a CI run is
   *  ALSO a docker run, so folding "ci" into the docker/host enum would destroy
   *  the distinction it exists to make. The two answer different questions —
   *  runtime = WHERE it ran, origin = WHO ran it.
   *
   *  `coerceEvent` preserves it verbatim (spread), so the arbiter needs no change. */
  origin?: "ci" | "local";

  /** Kind-specific detail, present only on kind "path_rewrite" (§2.4). Preserved
   *  verbatim by `coerceEvent` (spread), so the arbiter needs no change. */
  rewrite?: PathRewriteDetail;

  /** Structural request shape, present only on kind "tllm_call" (set by the
   *  model proxies) — the side-call detection seam. Preserved verbatim by
   *  `coerceEvent` (spread), so the arbiter needs no change. */
  callShape?: TllmCallShape;

  /** The evaluated security + utility checks, present only on kind "assertion"
   *  (§4.13) — the e2e suite's per-session verdict. Preserved verbatim by
   *  `coerceEvent` (spread), so the arbiter persists it opaquely. */
  assertions?: AssertionCheck[];

  /** The workspace files the harness prepared before the run, present only on
   *  kind "workspace_seed" (§4.11). Preserved verbatim by `coerceEvent`
   *  (spread), so the arbiter persists it opaquely. */
  seedFiles?: SeededFile[];

  /** Present only on kind "tool_result": the anthropic-proxy appended an
   *  `[mandu:twin]` note to this Bash result because the command read a
   *  whole-file symbol twin in the AgentView (symbol-twin-shell-blindness.md
   *  §4.6). `paths` are the model's own argv spellings, `tokens` the symbol
   *  count across them — never content. Preserved verbatim by `coerceEvent`
   *  (spread), so the arbiter persists it opaquely. */
  twinNote?: { paths: string[]; tokens: number; hinted?: number; more?: number; dirs?: number };
  /** Present only on kind "tool_result" (plan 10 §4.2): the confidentiality
   *  taint of the process tree behind a Bash result, by file and program
   *  name, with the output rule and whether the whole result was masked; and
   *  the `[mandu:secret]` note the model read (§11.8). Never content.
   *  Preserved verbatim by `coerceEvent` (spread). */
  secretTaint?: { level: string; files: string[]; apps: string[]; rule: string; maskWhole: boolean; denied: Array<{ path: string; app: string; reason: string }> };
  secretNote?: string;
  /** Present only on kind "session_level": the session's high-watermark
   *  before and after the raise, the symbol whose read raised it (a `$MDU:*`
   *  name, never its value) and where the session may still send (its
   *  bindings). Preserved verbatim by `coerceEvent` (spread). */
  sessionLevel?: { from: string; to: string; symbol: string | null; bindings: string[] };
  /** Present only on kind "prompt_filter" (confidentiality-plan-15 §8).
   *  Preserved verbatim by `coerceEvent` (spread). Never a value. */
  promptFilter?: PromptFilterDetail;
  /** Present only on kinds "launch_posture" (the launch's steps before the
   *  agent) and "session_exit" (the agent's run and the teardown steps):
   *  how long each named step of the launch took (the launcher's
   *  launch-timings.ts, runtime-instances.md §14.11). Display only, never a
   *  decision. Preserved verbatim by `coerceEvent` (spread). */
  timings?: LaunchTimingsDetail;

  /** The final per-view file trees at scenario end, present only on kind
   *  "workspace_final" (§4.12) — the seed's end-of-run twin, the Files tab's
   *  event-sourced fallback. Preserved verbatim by `coerceEvent` (spread), so
   *  the arbiter persists it opaquely. */
  finalViews?: FinalWorkspaceView[];

  /** The arbiter-admin audit-stream scalars, TOP-LEVEL on purpose: the SIEM
   *  rules key on them directly and the siem-exporter's redactor passes
   *  scalars through untouched (siem-integration.md §5). Preserved verbatim by
   *  `coerceEvent` (spread).
   *   - `posture` + `requestedBy` on kind "posture_change" (the arbiter's
   *     emitPostureChange — rule 100222 keys on posture=lockdown);
   *   - `axis`/`from`/`to`/`requestedBy` on kind "config_change" (the §4.19
   *     Protection drawer's config act — rules 100224/100225);
   *   - `promptAnswer` + `promptScope` on kind "approval_resolved" when the
   *     row is a prompt hold or a "let it through" (confidentiality-plan-15
   *     §13.9: the row's status alone cannot tell "send masked" from
   *     "cancel"). Never the span. */
  posture?: "normal" | "lockdown";
  axis?: "integrity" | "confidentiality";
  from?: boolean;
  to?: boolean;
  requestedBy?: string | null;
  promptAnswer?: "send" | "mask" | "cancel" | "let-through";
  promptScope?: "once" | "session";
}

// ── Builders / projectors — the arbiter→event seam ─────────────────────────────

/**
 * Construct a DualRepr from a symbolized and (optional) original string,
 * computing `differs` from the values so it can never drift out of sync with
 * them (§2.5 — `DualRepr.differs` consistent with `symbolized !== original`).
 */
export function makeDualRepr(
  symbolized: string,
  original: string | null,
  symbols: SymbolRef[] = [],
): DualRepr {
  return {
    symbolized,
    original,
    // When original is null we have nothing to compare against on this event,
    // so the panes are not "differing" in the side-by-side sense — they are
    // collapsed to the single symbolized view (with a privileged reveal on demand).
    differs: original !== null && symbolized !== original,
    symbols,
  };
}

/**
 * Project a arbiter symbol-table `SymbolEntry` (snake_case, the persisted shape)
 * onto a frontend `SymbolRef` (camelCase). This is the seam where the arbiter's
 * event-emission wave (Wave 3) maps its symbol table onto dashboard events; the
 * dashboard never imports better-sqlite3 or the arbiter package directly.
 *
 * Accepts a structurally-typed entry rather than importing the arbiter type so
 * the dashboard package stays dependency-free of the arbiter. The shape mirrors
 * arbiter/symbol-table/symbol-table.ts `SymbolEntry`.
 */
export interface ArbiterSymbolEntryLike {
  value: string;
  tool: string;
  field: string | null;
  origin: string | null;
  derived_from?: string | null;
  line_range?: string | null;
  /** Confidentiality level from the arbiter row (confidentiality.md §2). */
  confidentiality?: string | null;
}

export function fromSymbolEntry(name: string, e: ArbiterSymbolEntryLike): SymbolRef {
  const ref: SymbolRef = {
    name,
    tool: e.tool,
    field: e.field,
    origin: e.origin,
    value: e.value ?? null,
  };
  if (e.derived_from) ref.derivedFrom = e.derived_from;
  if (e.line_range) ref.lineRange = e.line_range;
  // Only a SECRET level is worth carrying: "public" is the absence of a claim,
  // and emitting it on every symbol would churn every event for nothing.
  if (e.confidentiality && e.confidentiality !== "public") {
    ref.confidentiality = e.confidentiality;
  }
  return ref;
}

/**
 * Minimal runtime validation used by the file-backed source when reading
 * append-only NDJSON written by other components. Returns the event if it has
 * the required structural fields, else null (the source skips bad lines rather
 * than throwing, mirroring the arbiter IPC's tolerant line parsing).
 */
export function isManduEvent(v: unknown): v is ManduEvent {
  if (v === null || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.id === "string" &&
    typeof e.sessionId === "string" &&
    typeof e.seq === "number" &&
    typeof e.ts === "string" &&
    typeof e.kind === "string" &&
    typeof e.view === "string" &&
    typeof e.invariant === "object" &&
    e.invariant !== null &&
    typeof (e.invariant as Record<string, unknown>).violatedInvariant === "boolean"
  );
}

// Per-kind defaults used to REPAIR events from emitters that omit the cross-cutting
// fields (the OS-interceptor traces care about their own payload, not the model-
// context boundary/emitter). Used only by coerceEvent below.
const BOUNDARY_BY_KIND: Partial<Record<EventKind, Boundary>> = {
  net_action: "network", fs_action: "filesystem", exec_action: "shell",
  tllm_call: "model_context", ullm_call: "model_context", tool_use: "model_context", tool_result: "model_context",
  path_rewrite: "model_context",
  approval_resolved: "model_context",
  approval_consumed: "model_context",
  posture_change: "model_context",
  config_change: "model_context",
  policy_model_call: "model_context",
  prompt_filter: "model_context",
  assertion: "model_context",
  workspace_seed: "filesystem",
  workspace_final: "filesystem",
};
const EMITTER_BY_KIND: Partial<Record<EventKind, Emitter>> = {
  net_action: "net-supervisor", fs_action: "fs-supervisor", exec_action: "exec-supervisor",
  tllm_call: "anthropic-proxy", ullm_call: "anthropic-proxy", tool_use: "anthropic-proxy", tool_result: "anthropic-proxy",
  path_rewrite: "anthropic-proxy",
  classify: "arbiter", symbolize: "arbiter", desymbolize: "arbiter", egress_request: "arbiter", egress_decision: "arbiter",
  approval_resolved: "arbiter",
  approval_consumed: "arbiter",
  posture_change: "arbiter",
  session_level: "arbiter",
  config_change: "dashboard",
  policy_model_call: "arbiter",
  assertion: "test-harness",
  workspace_seed: "test-harness",
  workspace_final: "test-harness",
  launch_posture: "launcher",
  session_exit: "launcher",
  relay_mode: "reply-filter",
  client_info: "anthropic-proxy",
  tool_surface: "anthropic-proxy",
  prompt_filter: "anthropic-proxy",
};

/**
 * Tolerant READ-path normalizer: coerce a raw record into a canonical
 * ManduEvent, repairing known emitter variances so EVERY chokepoint's
 * observability trace renders instead of being silently dropped:
 *
 *   - `ts` accepted as epoch-ms (number) → ISO 8601 (the net/fs/exec interceptors
 *     stamp `Date.now()`); a string ts is kept as-is.
 *   - a missing/!object `invariant` defaults to non-violated — an OS-interceptor
 *     action (net_action/fs_action/exec_action) is observability, not a model-
 *     context ingress, so it carries no §9 flag; rendering still needs the object
 *     (toCallDetail reads invariant.violatedInvariant) so we supply it.
 *   - absent ordering / lane / payload fields get renderer-safe defaults
 *     (seq/turn 0, callId/parentId/input/output null, boundary/emitter by kind).
 *
 * Returns null only when the core identity (id/sessionId/kind/view/ts) is
 * unrecoverable. `isManduEvent` stays the STRICT canonical predicate (used by
 * producers/tests); this is the tolerant consumer seam.
 */
export function coerceEvent(v: unknown): ManduEvent | null {
  if (v === null || typeof v !== "object") return null;
  const e = { ...(v as Record<string, unknown>) };
  if (typeof e.id !== "string" || typeof e.sessionId !== "string" ||
      typeof e.kind !== "string" || typeof e.view !== "string") return null;
  // ts: ISO string kept; epoch-ms number → ISO; anything else is unrecoverable.
  if (typeof e.ts === "number" && Number.isFinite(e.ts)) e.ts = new Date(e.ts).toISOString();
  else if (typeof e.ts !== "string") return null;
  // invariant: supply a non-violated default when an emitter omitted it.
  const inv = e.invariant as Record<string, unknown> | undefined;
  if (!inv || typeof inv !== "object" || typeof inv.violatedInvariant !== "boolean") {
    e.invariant = { violatedInvariant: false };
  }
  if (typeof e.seq !== "number") e.seq = 0;
  if (typeof e.turn !== "number") e.turn = 0;
  if (e.callId === undefined) e.callId = null;
  if (e.parentId === undefined) e.parentId = null;
  if (e.input === undefined) e.input = null;
  if (e.output === undefined) e.output = null;
  if (typeof e.boundary !== "string") e.boundary = BOUNDARY_BY_KIND[e.kind as EventKind] ?? "model_context";
  if (typeof e.emitter !== "string") e.emitter = EMITTER_BY_KIND[e.kind as EventKind] ?? "arbiter";
  return e as unknown as ManduEvent;
}

/** The events a dashboard DECISION may read: every one but a claim
 *  (`ManduEvent.claimed`, arbiter-human-plane.md §10.2). Display may show
 *  claims, marked as such; nothing that picks a folder, a repository, a
 *  reveal or a verdict reads one. */
export function believedEvents<T extends { claimed?: unknown }>(events: readonly T[]): T[] {
  return events.filter((e) => e.claimed !== true);
}
