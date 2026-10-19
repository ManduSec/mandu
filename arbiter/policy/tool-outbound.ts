/**
 * tool-outbound — tool-level outbound (data-usage / egress) spec.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/tool-outbound.ts
 *   Purpose: the DATA-USAGE policy table. Controls whether `$MDU:*` symbols
 *   in agent OUTBOUND data are resolved to raw values before the action executes.
 *   true  = resolve (destination is HumanView: external network / human-facing
 *           output / a live shell's stdin — the human-side needs real bytes).
 *   false = not_resolve (destination is the Agent File System — keep symbolic).
 *   Per-field overrides refine this at field granularity.
 *
 *   Adaptation for Mandu — FLAGGED:
 *     - Added a Claude-Code outbound spec (CLAUDE_CODE_OUTPUT_RESOLVE / _FIELD)
 *       mirroring tool-inbound.ts's claude-code re-map, and an active-spec swap
 *       (getActiveOutboundResolve / getActiveOutboundFieldPolicy /
 *       setActiveOutboundSpec) keyed off the SAME InboundSpecId so inbound and
 *       outbound stay on the same active ruleset. The arbiter default is
 *       claude-code; the OpenClaw maps are reachable for the reference suite.
 *     - The OpenClaw maps (TOOL_INPUT_RESOLVE / TOOL_INPUT_FIELD_POLICY) are
 *       preserved verbatim as the "openclaw" spec so the lifted reference tests
 *       keep their semantics.
 *     - Logger / runtime coupling: none — this file is pure data + a swap flag.
 *
 *   SECURITY NOTE: this table maps a tool/field to a DESTINATION KIND
 *   (HumanView vs AgentView). It does NOT itself decide approval — the egress
 *   gate (policy-interface.desymbolizationDecision) combines this destination
 *   kind with the symbol's UNTRUSTED provenance and the asCommand flag to
 *   require human approval. A "resolve" entry only means "this destination is
 *   human-facing"; whether an untrusted symbol may actually be resolved into it
 *   is the gate's fail-closed call.
 */

import type { InboundSpecId, SessionSpecLookup } from "./tool-inbound.js";
import { processSessionSpecs } from "./tool-inbound.js";
// The law in force (compiled-policy.ts) — a function-time-only cycle, safe.
import { getCurrentPolicy, recompileCurrentWithSpec } from "./compiled-policy.js";

export type InputFieldPolicy = "resolve" | "not_resolve" | "no_symbols_expected";

// ─── OpenClaw spec (reference, lifted verbatim) ──────────────────────────────

/**
 * Tool-level resolve policy.
 * true  = resolve (destination is human-view: external network, human-facing
 *         interface). false/absent = not resolve (destination is Agent FS).
 */
export const TOOL_INPUT_RESOLVE: Record<string, boolean> = {
  // External network
  web_fetch:    true,
  web_search:   true,

  // Exec (default/unrestricted mode) -- needs raw values for commands.
  // RESTRICTED=1 (AgentShell) is handled separately by the argv-mode path.
  exec:         true,

  // Process session control -- writes/paste/send-keys feed raw bytes into a
  // live shell session (same destination as exec), so symbols must be resolved.
  process:      true,

  // Image -- may fetch external URL
  image:        true,

  // Outbound to user
  message:      true,
  tts:          true,
};

/**
 * Per-field input symbolization policy. Determines how each field in tool input
 * params is handled when `$MDU:` symbols are present.
 */
export const TOOL_INPUT_FIELD_POLICY: Record<string, Record<string, InputFieldPolicy>> = {
  // Filesystem tools -- symbolized execution (AgentView)
  read:           { file_path: "not_resolve", path: "not_resolve" },
  write:          { file_path: "not_resolve", path: "not_resolve", content: "not_resolve" },
  edit:           {
    file_path: "not_resolve",
    path: "not_resolve",
    old_string: "not_resolve",
    oldText: "not_resolve",
    new_string: "not_resolve",
    newText: "not_resolve",
  },

  // External network -- resolve for HTTP requests
  web_fetch:      { url: "resolve", extractMode: "resolve", maxChars: "resolve" },
  web_search:     { query: "resolve" },

  // Exec -- the command field is resolved (HumanShell) in unrestricted mode.
  exec:           { command: "resolve", workdir: "resolve" },

  // Process -- all content fields that land on a live shell's stdin get
  // resolved (destination is human-view: the PTY/subprocess).
  process:        {
    action:      "resolve",
    sessionId:   "resolve",
    data:        "resolve",
    keys:        "resolve",
    hex:         "resolve",
    literal:     "resolve",
    text:        "resolve",
    bracketed:   "resolve",
    eof:         "resolve",
    offset:      "resolve",
    limit:       "resolve",
    timeout:     "resolve",
  },

  // Image -- resolve for external URL
  image:          { image: "resolve" },

  // Outbound to user -- resolve so the user sees raw values
  message:        { message: "resolve", channel: "resolve", target: "resolve", caption: "resolve" },
  tts:            { text: "resolve" },

  // Sessions -- mixed per-field
  sessions_send:  { sessionKey: "resolve", message: "not_resolve" },
  sessions_spawn: { task: "not_resolve", label: "not_resolve", agentId: "resolve", cwd: "not_resolve" },

  // Local tools -- symbolized execution
  memory_search:  { query: "not_resolve" },
  memory_get:     { file: "not_resolve" },
  inspect_symbol: { symbols: "not_resolve", prompt: "not_resolve" },
};

// ─── Claude Code spec (Mandu default) ──────────────────────────────────────

/**
 * Claude Code outbound resolve map. Tool-level destination kinds:
 *   - WebFetch / WebSearch → HumanView network → resolve.
 *   - Bash                 → HumanShell egress (argv/code) → resolve.
 *   - Read / Write / Edit / MultiEdit / NotebookEdit → Agent File System → keep
 *     symbolic (not_resolve).
 * Tools absent here default to NOT resolving (Agent FS / symbolized), which is
 * the safe destination.
 */
export const CLAUDE_CODE_OUTPUT_RESOLVE: Record<string, boolean> = {
  WebFetch:  true,
  WebSearch: true,
  Bash:      true,
};

export const CLAUDE_CODE_OUTPUT_FIELD_POLICY: Record<string, Record<string, InputFieldPolicy>> = {
  // Filesystem tools -- Agent File System, keep symbolic.
  Read:         { file_path: "not_resolve" },
  Write:        { file_path: "not_resolve", content: "not_resolve" },
  Edit:         { file_path: "not_resolve", old_string: "not_resolve", new_string: "not_resolve" },
  MultiEdit:    { file_path: "not_resolve" },
  NotebookEdit: { notebook_path: "not_resolve", new_source: "not_resolve" },

  // External network -- HumanView, resolve.
  WebFetch:     { url: "resolve", prompt: "resolve" },
  WebSearch:    { query: "resolve" },

  // Shell -- HumanShell, the command string is resolved (gated by the egress
  // gate, which requires approval for an untrusted symbol used as command).
  Bash:         { command: "resolve" },
};

// ─── OpenCode spec ───────────────────────────────────────────────────────────

/**
 * OpenCode outbound resolve map. Same destination-kind reasoning as Claude
 * Code, against OpenCode's tool names (read off the wire — see
 * opencode-inbound.ts):
 *   - webfetch / websearch → HumanView network → resolve.
 *   - bash                 → HumanShell egress (argv/code) → resolve.
 *   - read / write / edit / apply_patch → Agent File System → keep symbolic.
 * Tools absent here default to NOT resolving, which is the safe destination.
 */
export const OPENCODE_OUTPUT_RESOLVE: Record<string, boolean> = {
  webfetch: true,
  websearch: true,
  bash: true,
  // OpenCode 2's name for bash (2.0.23; opencode-inbound.ts header)
  shell: true,
};

export const OPENCODE_OUTPUT_FIELD_POLICY: Record<string, Record<string, InputFieldPolicy>> = {
  // Filesystem tools -- Agent File System, keep symbolic. NB `filePath`
  // (camelCase) is OpenCode 1's spelling, `path` OpenCode 2's (2.0.23); the
  // Claude Code `file_path` key would never match.
  read: { filePath: "not_resolve", path: "not_resolve" },
  write: { filePath: "not_resolve", path: "not_resolve", content: "not_resolve" },
  edit: { filePath: "not_resolve", path: "not_resolve", oldString: "not_resolve", newString: "not_resolve" },
  apply_patch: { filePath: "not_resolve", patch: "not_resolve" },

  // Search -- the pattern is matched against Agent-FS content, so a symbol in
  // it stays symbolic (mirrors the reference spec's memory_search posture).
  glob: { pattern: "not_resolve", path: "not_resolve" },
  grep: { pattern: "not_resolve", path: "not_resolve", include: "not_resolve" },

  // External network -- HumanView, resolve.
  webfetch: { url: "resolve", format: "resolve" },
  websearch: { query: "resolve" },

  // Shell -- HumanShell, the command string is resolved (gated by the egress
  // gate, which requires approval for an untrusted symbol used as command).
  bash: { command: "resolve", workdir: "resolve" },
  shell: { command: "resolve", workdir: "resolve" },
};

// ─── Goose spec ──────────────────────────────────────────────────────────────

/**
 * Goose outbound resolve map (goose 1.53.0's wire, goose-inbound.ts). Only the
 * shell is a HumanShell egress whose command is resolved (and gated by the
 * egress gate). `write` / `edit` / `tree` act on the Agent File System and
 * keep symbols symbolic; `read_image`'s `source` (a path or a URL) is left
 * symbolic too, the safe default for every tool absent here.
 */
export const GOOSE_OUTPUT_RESOLVE: Record<string, boolean> = {
  shell: true,
};

export const GOOSE_OUTPUT_FIELD_POLICY: Record<string, Record<string, InputFieldPolicy>> = {
  // Filesystem tools -- Agent File System, keep symbolic.
  write: { path: "not_resolve", content: "not_resolve" },
  edit: { path: "not_resolve", before: "not_resolve", after: "not_resolve" },
  tree: { path: "not_resolve" },
  // Shell -- HumanShell, the command string is resolved (gated by the egress
  // gate, which requires approval for an untrusted symbol used as command).
  shell: { command: "resolve" },
};

// ─── Active-spec swap (keyed off the SAME InboundSpecId) ──────────────────────

const OUTBOUND_RESOLVE: Record<InboundSpecId, Record<string, boolean>> = {
  "claude-code": CLAUDE_CODE_OUTPUT_RESOLVE,
  openclaw: TOOL_INPUT_RESOLVE,
  // OpenClaw-as-defended-agent reuses the lifted OUTBOUND maps verbatim: the
  // tool names are identical, and the inbound divergence that forced a separate
  // spec (wholesale-trusted `read`) is a TRUST question, not a DESTINATION-KIND
  // question. Egress semantics are unchanged between the two.
  "openclaw-agent": TOOL_INPUT_RESOLVE,
  opencode: OPENCODE_OUTPUT_RESOLVE,
  goose: GOOSE_OUTPUT_RESOLVE,
  // The AgentDojo eval specs (docs/design/testing/evaluation.md §2): no per-tool
  // outbound resolve rules — the defense being measured is INGRESS
  // symbolization, and an empty map keeps egress fail-closed (no field is
  // auto-desymbolized, so an untrusted symbol reaching a sink argument falls to
  // the default require-approval usage decision).
  agentdojo: {},
  "fail-closed": {},
};

const OUTBOUND_FIELD_POLICY: Record<InboundSpecId, Record<string, Record<string, InputFieldPolicy>>> = {
  "claude-code": CLAUDE_CODE_OUTPUT_FIELD_POLICY,
  openclaw: TOOL_INPUT_FIELD_POLICY,
  "openclaw-agent": TOOL_INPUT_FIELD_POLICY,
  opencode: OPENCODE_OUTPUT_FIELD_POLICY,
  goose: GOOSE_OUTPUT_FIELD_POLICY,
  agentdojo: {},
  "fail-closed": {},
};

/** The PRISTINE built-in tables — inputs to `compilePolicy` (compiled-policy.ts).
 *  Never mutated: overrides apply to copies; the accessors below read the law
 *  in force. Inbound and outbound share ONE boot spec in the compiled law. */
export const BUILTIN_OUTBOUND_RESOLVE: Readonly<Record<InboundSpecId, Readonly<Record<string, boolean>>>> = OUTBOUND_RESOLVE;
export const BUILTIN_OUTBOUND_FIELD_POLICY: Readonly<
  Record<InboundSpecId, Readonly<Record<string, Readonly<Record<string, InputFieldPolicy>>>>>
> = OUTBOUND_FIELD_POLICY;

/** The boot spec's tool-level outbound resolve map in the law in force (frozen). */
export function getActiveOutboundResolve(): Readonly<Record<string, boolean>> {
  const c = getCurrentPolicy();
  return c.outboundResolve[c.specId];
}

/** The boot spec's per-field outbound policy map in the law in force (frozen). */
export function getActiveOutboundFieldPolicy(): Readonly<Record<string, Readonly<Record<string, InputFieldPolicy>>>> {
  const c = getCurrentPolicy();
  return c.outboundFieldPolicy[c.specId];
}

/** Which outbound spec is active — the same id as the inbound one. */
export function getActiveOutboundSpecId(): InboundSpecId {
  return getCurrentPolicy().specId;
}

/** Same as setActiveInboundSpec — one spec id governs both directions; kept
 *  for callers that switch them in pairs. */
export function setActiveOutboundSpec(id: InboundSpecId): void {
  if (getCurrentPolicy().specId !== id) recompileCurrentWithSpec(id);
}

/**
 * Resolve the effective destination kind for a tool/field on egress.
 *
 * Returns "resolve" when the destination is HumanView (external network / human
 * output / live shell), "not_resolve" when it is the Agent File System
 * (symbolized), or "no_symbols_expected".
 *
 * Resolution order (fail-safe toward NOT resolving):
 *   1. explicit per-field entry in the active field-policy map;
 *   2. the tool-level resolve flag (true → "resolve", false/absent →
 *      "not_resolve");
 *   3. a tool with NO entry at all → "not_resolve" (treat unknown destinations
 *      as the symbolized Agent FS — the safe side: an unknown sink does not get
 *      raw bytes without the gate's say-so).
 *
 * Session-keyed (agent-e2e-harness.md §7.1): a session bound via the
 * `setSessionSpec` IPC op resolves against ITS spec's outbound maps — the
 * binding (one arbiter's `SessionSpecs`, tool-inbound.ts) is shared because
 * inbound and outbound are always switched together (one InboundSpecId keys
 * both). Unbound/absent falls back to the process-global active outbound
 * spec, byte-identical to before.
 */
export function destinationKind(
  tool: string,
  field: string | undefined,
  sessionKey?: string,
  specs: SessionSpecLookup = processSessionSpecs,
): InputFieldPolicy {
  const c = getCurrentPolicy();
  const specId = (sessionKey !== undefined ? specs.specOf(sessionKey) : undefined) ?? c.specId;
  const fields = c.outboundFieldPolicy[specId][tool];
  if (field && fields && field in fields) return fields[field]!;
  const toolLevel = c.outboundResolve[specId][tool];
  if (toolLevel === true) return "resolve";
  return "not_resolve";
}
