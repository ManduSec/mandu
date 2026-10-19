/**
 * tool-inbound — the DEFAULT per-tool inbound schema ruleset (starting policy).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/tool-inbound.ts
 *   Purpose: TOOL_INBOUND_SPEC is the evaluated default ruleset that load-policy
 *   / policy-engine consume — it maps each tool's result fields to trust
 *   categories (schema rules) and origin keys. resolve-schema.ts walks these.
 *   This is the data-trust policy's "real rules to run" that the M0 stub lacked.
 *
 *   Adaptation for Mandu: NONE to the rules themselves — the schemas are
 *   lifted verbatim so the evaluated classification behavior carries over. Only
 *   the surrounding prose was trimmed to drop references to OpenClaw-internal
 *   modules (worktree path-rewrite hook, index.ts symbolic-exec mode) that do
 *   not exist in Mandu yet; the security rationale per tool is preserved.
 *
 * RE-MAP STATUS (the original TODO here, now DONE — completed 2026-07-16):
 *   This ruleset is written for OpenClaw's ~21 tools (web_fetch, web_search,
 *   message, process, sessions_*, exec, …). Mandu targets CLAUDE CODE, whose
 *   tool surface is mapped in arbiter/policy/claude-code-inbound.ts —
 *   CLAUDE_CODE_INBOUND_SPEC is the ACTIVE DEFAULT below. That file covers the
 *   real recorded tool surface (Read/NotebookRead, Write/Edit/MultiEdit/
 *   NotebookEdit/TodoWrite, Bash/BashOutput/KillShell, Glob/Grep/LS,
 *   WebFetch/WebSearch, Task/Agent/TaskOutput, AskUserQuestion/ExitPlanMode,
 *   SlashCommand/Skill, mcp__* by prefix) and documents, per tool, the
 *   provenance justification for every TRUSTED grant and what deliberately
 *   stays fail-closed. Any Claude Code tool name NOT present there still falls
 *   through to the FAIL-CLOSED UNTRUSTED default in policy-interface.ts — safe
 *   (over-symbolizing), never under-symbolizing. The OpenClaw names below are
 *   kept so the lifted mechanism stays exercised + tested and remains a
 *   faithful reference (selectable via setActiveInboundSpec("openclaw")).
 */

import type {
  SchemaNode,
  ActionToolInboundSpec,
  ToolSpec,
} from "./schema-types.js";
import {
  CLAUDE_CODE_INBOUND_SPEC,
  MCP_TOOL_PREFIX,
  MCP_INBOUND_SPEC,
} from "./claude-code-inbound.js";
import {
  AGENTDOJO_INBOUND_SPEC,
  FAIL_CLOSED_INBOUND_SPEC,
} from "./agentdojo-inbound.js";
import { OPENCODE_INBOUND_SPEC } from "./opencode-inbound.js";
import { GOOSE_INBOUND_SPEC } from "./goose-inbound.js";
import { OPENCLAW_AGENT_INBOUND_SPEC } from "./openclaw-inbound.js";
import { isManduDeclassifyTool, isManduInspectTool } from "./inspect-tool.js";
import { isManduPolicyTool } from "./policy-tool.js";
// The law in force (compiled-policy.ts). A module cycle — compiled-policy
// imports the built-in tables from here — but both sides touch the other only
// inside functions, never at module evaluation, so import order is irrelevant.
import { getCurrentPolicy, recompileCurrentWithSpec } from "./compiled-policy.js";

export const TOOL_INBOUND_SPEC: Record<string, ToolSpec> = {
  // ── Local filesystem / system ─────────────────────────────────────────
  // `read` returns trusted text in full mode. DIR-untrusted files are handled
  // out-of-band by the FS view-sync (the agent view already contains a symbol
  // token), so the read result carries the symbol verbatim. In dual-only mode
  // those FS layers are disabled, so local file reads remain trusted.
  read: {
    paramsKeys: { file_path: { category: "DIR", role: "key" } },
    schema: "TRUSTED",
  },
  write:          { schema: "TRUSTED" },
  edit:           { schema: "TRUSTED" },
  memory_search:  { schema: "TRUSTED" },
  memory_get:     { schema: "TRUSTED" },
  session_status: { schema: "TRUSTED" },
  canvas:         { schema: "TRUSTED" },
  nodes:          { schema: "TRUSTED" },
  cron:           { schema: "TRUSTED" },
  tts:            { schema: "TRUSTED" },

  // ── External network ──────────────────────────────────────────────────
  // For web_fetch we key title/text off params.url rather than the
  // echoed body field so summarizeToolTrust (which runs without the
  // parsed body) can answer correctly.
  web_fetch: {
    paramsKeys: { url: { category: "URL", role: "key" } },
    schema: {
      url:             { category: "URL", role: "key" },
      finalUrl:        { category: "URL", role: "key" },
      status:          "TRUSTED",
      contentType:     "TRUSTED",
      extractMode:     "TRUSTED",
      extractor:       "TRUSTED",
      fetchedAt:       "TRUSTED",
      tookMs:          "TRUSTED",
      truncated:       "TRUSTED",
      length:          "TRUSTED",
      rawLength:       "TRUSTED",
      wrappedLength:   "TRUSTED",
      externalContent: "TRUSTED",
      title:           { category: "URL", role: "data", keyField: "params.url" },
      text:            { category: "URL", role: "data", keyField: "params.url" },
      warning:         "TRUSTED",
    } satisfies SchemaNode,
  },

  // Per-item URL trust is expressed directly in the schema — the
  // resolver walks __items and resolves keyField "url" against each
  // item.
  web_search: {
    schema: {
      query:           "TRUSTED",
      provider:        "TRUSTED",
      count:           "TRUSTED",
      tookMs:          "TRUSTED",
      externalContent: "TRUSTED",
      results: {
        __items: {
          url:         { category: "URL", role: "key" },
          published:   "TRUSTED",
          siteName:    "TRUSTED",
          title:       { category: "URL", role: "data", keyField: "url" },
          description: { category: "URL", role: "data", keyField: "url" },
        },
      },
    } satisfies SchemaNode,
  },

  // ── Exec / image ──────────────────────────────────────────────────────
  // Exec is plaintext UNTRUSTED by default (may read attacker-controlled
  // data via the shell). Symbolic exec mode is an M3 concern (exec policy).
  exec: { schema: "UNTRUSTED" },

  // `process` manages long-running exec sessions. Result shape depends on
  // params.action: read-style actions (`poll`, `log`) return shell
  // stdout/stderr from an attacker-reachable session — same threat model
  // as `exec`, so UNTRUSTED. Write/lifecycle actions return only
  // tool-generated metadata and are TRUSTED. `list` returns registry
  // metadata and is TRUSTED. Unknown actions fall through to
  // defaultSchema = UNTRUSTED (fail-closed).
  process: {
    actionField: "action",
    schemas: {
      list:        "TRUSTED",
      poll:        "UNTRUSTED",
      log:         "UNTRUSTED",
      write:       "TRUSTED",
      "send-keys": "TRUSTED",
      submit:      "TRUSTED",
      paste:       "TRUSTED",
      kill:        "TRUSTED",
      clear:       "TRUSTED",
      remove:      "TRUSTED",
    },
    defaultSchema: "UNTRUSTED",
  } satisfies ActionToolInboundSpec,

  // Image vision analysis: body is free-form text, trust decided by the
  // source URL category.
  image: {
    paramsKeys: { image: { category: "URL", role: "key" } },
    schema: { category: "URL", role: "data", keyField: "params.image" },
  },

  // ── Sessions ──────────────────────────────────────────────────────────
  sessions_send: {
    paramsKeys: { sessionKey: { category: "CHANNEL", role: "key" } },
    schema: {
      runId:      "TRUSTED",
      status:     "TRUSTED",
      sessionKey: "TRUSTED",
      delivery:   "TRUSTED",
      reply:      { category: "CHANNEL", role: "data", keyField: "params.sessionKey" },
    } satisfies SchemaNode,
  },

  sessions_history: {
    paramsKeys: { sessionKey: { category: "CHANNEL", role: "key" } },
    schema: {
      sessionKey:       "TRUSTED",
      truncated:        "TRUSTED",
      droppedMessages:  "TRUSTED",
      contentTruncated: "TRUSTED",
      contentRedacted:  "TRUSTED",
      bytes:            "TRUSTED",
      messages: {
        __items: {
          role:      "TRUSTED",
          timestamp: "TRUSTED",
          content: {
            __items: {
              type: "TRUSTED",
              text: { category: "CHANNEL", role: "data", keyField: "params.sessionKey" },
            },
          },
        },
      },
    } satisfies SchemaNode,
  },

  sessions_spawn: { schema: "TRUSTED" },
  sessions_list:  { schema: "TRUSTED" },
  subagents:      { schema: "TRUSTED" },

  // message tool: result shape depends on params.action. Read-style
  // actions pull data from a channel (CHANNEL data). Write/meta actions
  // return trusted metadata.
  message: {
    paramsKeys: {
      channel: { category: "CHANNEL", role: "key" },
      target:  { category: "CHANNEL", role: "key" },
    },
    actionField: "action",
    schemas: {
      read:            { category: "CHANNEL", role: "data", keyField: "params.channel" },
      search:          { category: "CHANNEL", role: "data", keyField: "params.channel" },
      "thread-list":   { category: "CHANNEL", role: "data", keyField: "params.channel" },
      "list-pins":     { category: "CHANNEL", role: "data", keyField: "params.channel" },
      "download-file": { category: "CHANNEL", role: "data", keyField: "params.channel" },
      send:   "TRUSTED",
      delete: "TRUSTED",
      react:  "TRUSTED",
      pin:    "TRUSTED",
      unpin:  "TRUSTED",
      edit:   "TRUSTED",
      reply:  "TRUSTED",
    },
    defaultSchema: "TRUSTED",
  } satisfies ActionToolInboundSpec,

  // ── Nested-agent containers ───────────────────────────────────────────
  claude_code_run:    { schema: "TRUSTED" },
  claude_code_status: { schema: "TRUSTED" },
  claude_code_browse: { schema: "TRUSTED" },
  claude_code_list:   { schema: "TRUSTED" },
  claude_code_stop:   { schema: "TRUSTED" },
  claude_code_assign: { schema: "TRUSTED" },
  claude_code_delete: { schema: "TRUSTED" },

  // ── Mandu internal tools ───────────────────────────────────────────────
  inspect_symbol: { schema: "TRUSTED" },
  policy_list:    { schema: "TRUSTED" },
  policy_add:     { schema: "TRUSTED" },
  policy_del:     { schema: "TRUSTED" },
};

// ─── Active inbound spec selection (Mandu adaptation) ──────────────────────
//
// Mandu targets Claude Code, so CLAUDE_CODE_INBOUND_SPEC is the ACTIVE DEFAULT.
// The lifted OpenClaw TOOL_INBOUND_SPEC is retained and remains selectable for
// reference + tests via setActiveInboundSpec("openclaw"). The active map is the
// one getToolInboundSpec consults and the one YAML `tools:` overrides
// (tool-overrides.ts) mutate — so overrides always land on the live ruleset.

export type InboundSpecId =
  | "claude-code"
  | "openclaw"
  | "openclaw-agent"
  | "opencode"
  | "goose"
  | "agentdojo"
  | "fail-closed";

const INBOUND_SPECS: Record<InboundSpecId, Record<string, ToolSpec>> = {
  "claude-code": CLAUDE_CODE_INBOUND_SPEC,
  // The LIFTED reference ruleset, kept faithful (two arbiter unit tests pin it).
  // It is NOT what Mandu uses to defend a live OpenClaw CLI — see below.
  openclaw: TOOL_INBOUND_SPEC,
  // OpenClaw as a DEFENDED AGENT, proxy-only posture. Distinct from `openclaw`
  // because the lifted spec trusts `read` wholesale — safe only under the
  // reference plugin's FS view-sync, a security regression without it.
  // openclaw-inbound.ts's header has the full argument.
  "openclaw-agent": OPENCLAW_AGENT_INBOUND_SPEC,
  // OpenCode (npm opencode-ai) — tool names read off the wire, not from docs;
  // see opencode-inbound.ts. Selected by the opencode-e2e live suite via its
  // own private arbiter (docs/design/testing/agent-e2e-harness.md §4).
  opencode: OPENCODE_INBOUND_SPEC,
  // Goose (aaif-goose, the `goose` CLI) — tool names read off the wire
  // (goose 1.53.0, 2026-10-05); see goose-inbound.ts. Bound by the launcher
  // for `mandu goose` (context-proxy.ts) and by the goose replay drills.
  goose: GOOSE_INBOUND_SPEC,
  // The AgentDojo benchmark specs (docs/design/testing/evaluation.md §2). "agentdojo"
  // is the calibrated operating point; "fail-closed" is the empty map that
  // symbolizes every tool output (the conservative security bound). Both are
  // selected for the eval only; the live default stays "claude-code".
  agentdojo: AGENTDOJO_INBOUND_SPEC,
  "fail-closed": FAIL_CLOSED_INBOUND_SPEC,
};

/** Every known spec id, derived from the registry (no hand-kept twin list). */
export const INBOUND_SPEC_IDS = Object.keys(INBOUND_SPECS) as readonly InboundSpecId[];

/** Type guard for wire/env values naming a spec. */
export function isInboundSpecId(v: string): v is InboundSpecId {
  return Object.prototype.hasOwnProperty.call(INBOUND_SPECS, v);
}

/** The PRISTINE built-in tables — the input to `compilePolicy`
 *  (compiled-policy.ts). Never mutated: overrides apply to copies, and the
 *  "active" accessors below read the compiled law in force. */
export const BUILTIN_INBOUND_SPECS: Readonly<Record<InboundSpecId, Readonly<Record<string, ToolSpec>>>> = INBOUND_SPECS;

// ─── Session-keyed spec bindings (agent-e2e-harness.md §7.1) ─────────────────
//
// One arbiter serving MIXED agents needs per-session trust specs: tool names
// differ per agent (`Read` vs `read`; `Bash` vs `exec` vs `bash`), and a wrong
// spec over-symbolizes at best (fail-closed, safe) but destroys the
// trusted-verbatim utility half. The binding is keyed by the same session
// identity the proxies already thread into the security path (the launcher's
// MANDU_SESSION_KEY / scopeId), set via the `setSessionSpec` IPC op, and
// consulted with FALLBACK to the process-global boot spec — so an unbound or
// unknown session behaves exactly as before bindings existed. In-memory only:
// after an arbiter restart a formerly-bound non-Claude session falls back to
// the global spec, where its foreign tool names miss every entry and classify
// fail-closed UNTRUSTED — degradation is toward over-symbolization, never
// under. YAML `tools:` overrides (tool-overrides.ts) keep mutating the
// process-global ACTIVE map only; a session bound to the same id as the active
// spec sees the merged view (same object), a session bound to a different id
// sees that spec's base rules. `snapshotActivePolicy` likewise reports the
// global spec — per-session snapshot plumbing is deliberately not built until
// something reads it.
//
// SCOPE (2026-10-09, agent-e2e-harness.md §4): the bindings belong to ONE
// arbiter. Each ArbiterServer owns a `SessionSpecs` registry, hands it to the
// engine it builds (createEngineBackedPolicy's `sessionSpecs`) and to every
// session-keyed lookup it makes itself, and clears it on close. They used to
// be a map in this module, so they outlived the server that made them: the
// in-process arbiters of one test process shared them, and a fresh arbiter
// refused a bind another one had made ("already bound … specs are
// bind-once"), or resolved a session by another arbiter's binding. The
// process registry below (`processSessionSpecs`) remains only for DIRECT
// callers of the pure lookups (unit tests, embedders of the bare engine); no
// ArbiterServer reads or writes it.

/** The read side of a session→spec registry: what resolution needs. */
export interface SessionSpecLookup {
  /** The spec id a session is bound to, if any (no fallback — callers that
   *  want the effective id use resolveInboundSpecId). */
  specOf(sessionKey: string): InboundSpecId | undefined;
}

/** The outcome of {@link SessionSpecs.bind}. */
export type SessionSpecBind =
  | { ok: true; already: boolean }
  | { ok: false; prior: InboundSpecId };

/**
 * One arbiter's session→spec bindings. BIND-ONCE (policy-surface.md §2.6):
 * the first binding of a session wins for the registry's life; the same id
 * again is an idempotent no-op; a different id is refused and the binding
 * stays as it was. Nothing unbinds one session: only `clear()` (the owning
 * server's close, or a test's teardown) drops them, all at once. The other
 * refusal (no bind after a session's first classify) needs the server's
 * traffic record and lives in its `setSessionSpec` handler.
 */
export class SessionSpecs implements SessionSpecLookup {
  private readonly bound = new Map<string, InboundSpecId>();

  /** Bind `sessionKey` to `id`, bind-once (see the class). */
  bind(sessionKey: string, id: InboundSpecId): SessionSpecBind {
    const prior = this.bound.get(sessionKey);
    if (prior !== undefined) return prior === id ? { ok: true, already: true } : { ok: false, prior };
    this.bound.set(sessionKey, id);
    return { ok: true, already: false };
  }

  specOf(sessionKey: string): InboundSpecId | undefined {
    return this.bound.get(sessionKey);
  }

  /** Current bindings (observability / tests). */
  bindings(): ReadonlyMap<string, InboundSpecId> {
    return this.bound;
  }

  /** Drop every binding: the owning server's close, or a test's teardown. */
  clear(): void {
    this.bound.clear();
  }
}

/** The PROCESS registry: the default of every session-keyed lookup, for
 *  direct callers of the pure policy (unit tests, embedders of the bare
 *  engine). An ArbiterServer never uses it: it passes its own registry
 *  everywhere. */
export const processSessionSpecs = new SessionSpecs();

/** Bind a session in the PROCESS registry (direct callers only; an arbiter
 *  binds in its own). Also keys the outbound maps — the two are always
 *  switched together, see tool-outbound.ts. Bind-once: another spec for a
 *  bound session throws. */
export function bindSessionSpec(sessionKey: string, id: InboundSpecId): void {
  const r = processSessionSpecs.bind(sessionKey, id);
  if (!r.ok) throw new Error(`bindSessionSpec: ${sessionKey} already bound to '${r.prior}' — specs are bind-once`);
}

/** The spec id a session is bound to in the PROCESS registry, if any. */
export function sessionSpecOf(sessionKey: string): InboundSpecId | undefined {
  return processSessionSpecs.specOf(sessionKey);
}

/** The PROCESS registry's bindings (observability / tests). */
export function sessionSpecBindings(): ReadonlyMap<string, InboundSpecId> {
  return processSessionSpecs.bindings();
}

/** Test teardown: drop the PROCESS registry's bindings. */
export function clearSessionSpecs(): void {
  processSessionSpecs.clear();
}

/** The effective inbound spec id for a session: its binding in `specs`, else
 * the process-global active spec (exactly the pre-session-keying behavior). */
export function resolveInboundSpecId(sessionKey?: string, specs: SessionSpecLookup = processSessionSpecs): InboundSpecId {
  if (sessionKey !== undefined) {
    const bound = specs.specOf(sessionKey);
    if (bound !== undefined) return bound;
  }
  return getCurrentPolicy().specId;
}

/** The boot spec's tool-spec table in the law in force (overrides applied,
 *  frozen). Defaults to Claude Code. */
export function getActiveInboundSpec(): Readonly<Record<string, ToolSpec>> {
  const c = getCurrentPolicy();
  return c.inbound[c.specId];
}

/** Which inbound spec is active. */
export function getActiveInboundSpecId(): InboundSpecId {
  return getCurrentPolicy().specId;
}

/** Swap the active inbound spec: recompiles the current document under `id`
 *  and swaps the law in force (policy-surface.md §2.2) — no table is
 *  mutated. Mandu defaults to "claude-code"; pass "openclaw" to exercise the
 *  lifted reference map. */
export function setActiveInboundSpec(id: InboundSpecId): void {
  if (getCurrentPolicy().specId !== id) recompileCurrentWithSpec(id);
}

/**
 * Narrow by tool name against the ACTIVE inbound spec. Returns undefined for
 * unclassified tools (which the caller MUST treat as fail-closed UNTRUSTED —
 * see policy-interface.ts).
 *
 * mcp__ PREFIX MATCH (Mandu adaptation): the reference resolver matches tool
 * names EXACTLY. Claude Code reports MCP tools as `mcp__<server>__<tool>`, an
 * unbounded family we cannot enumerate. We extend the lookup MINIMALLY: after
 * an exact-name miss, any name beginning with MCP_TOOL_PREFIX maps to the
 * whole-result UNTRUSTED MCP_INBOUND_SPEC. An explicit per-MCP-tool entry in the
 * active map (e.g. from a YAML override) still wins via the exact-match path, so
 * the prefix rule is a fail-closed fallback, never an override of intent. The
 * prefix rule applies only when the Claude Code spec is active (MCP tools are a
 * Claude Code concept); under the OpenClaw spec, names fall through unmatched.
 *
 * ONE content-shape refinement lives downstream: when this lookup resolves to
 * MCP_INBOUND_SPEC for the Mandu-internal inspect tool
 * (MANDU_INSPECT_TOOL), classify() in policy-interface.ts applies the hybrid
 * exact-name + pure-symbolic-shape rule instead of the blanket UNTRUSTED —
 * see claude-code-inbound.ts classifyManduInspectResult (an explicit
 * exact-name entry here still wins, since it bypasses the prefix fallback).
 */
export function getToolInboundSpec(
  toolName: string,
  sessionKey?: string,
  specs: SessionSpecLookup = processSessionSpecs,
): ToolSpec | undefined {
  // Session-keyed resolution (one arbiter, mixed agents): the session's bound
  // spec wins; unbound/absent falls back to the process-global active spec.
  // The mcp__ prefix gate is keyed off the SAME resolved id — a claude-code
  // session on a mixed arbiter keeps its MCP fallback, and a session bound to
  // any other spec never inherits it (MCP tools are a Claude Code concept).
  const specId = resolveInboundSpecId(sessionKey, specs);
  const exact = getCurrentPolicy().inbound[specId][toolName];
  if (exact !== undefined) return exact;
  // Mandu's OWN inspect channel, under whichever name this agent's runtime
  // gives it (inspect-tool.ts owns the exact-name set: `mcp__…__inspect_symbol`
  // on Claude Code, `mandu-inspect_inspect_symbol` on OpenCode, bare
  // `inspect_symbol` on OpenClaw's plugin). Spec-INDEPENDENT because Mandu
  // mounts this tool itself on every agent — the downstream refinement in
  // policy-interface.ts is what actually decides, and it trusts nothing but the
  // pure-symbolic envelope. Checked AFTER the exact-name lookup, so a YAML
  // override still wins.
  if (isManduInspectTool(toolName)) return MCP_INBOUND_SPEC;
  // Its rung-3 sibling `declassify_symbol`, under the same spellings
  // (`mandu-inspect_declassify_symbol` on OpenCode, bare `declassify_symbol`
  // on OpenClaw's plugin): the SAME whole-result UNTRUSTED object a Claude
  // Code session reaches through the mcp__ fallback, so every agent gets one
  // verdict. Nothing is trusted by this mapping: the only way a declassify
  // result passes is the arbiter's own check that it is exactly the value
  // released to that session (server.ts declassifyResultTrusted). Mapping it
  // keeps the tool off the session-health "unknown tools" list. The input
  // scan (inboundSpecNamesInput) stays as for Claude Code.
  if (isManduDeclassifyTool(toolName)) return MCP_INBOUND_SPEC;
  // The Mandu POLICY tools (policy-tool.ts): same spec-independent routing
  // as the inspect channel; the refinement in policy-interface.ts decides, and
  // trusts nothing but a well-formed token-only envelope.
  if (isManduPolicyTool(toolName)) return MCP_INBOUND_SPEC;
  if (specId === "claude-code" && toolName.startsWith(MCP_TOOL_PREFIX)) {
    return MCP_INBOUND_SPEC;
  }
  return undefined;
}

/**
 * Does this session's spec name the tool's INPUT, so the path-ish params the
 * confidentiality derivation reads (`file_path`, `path`, `notebook_path`,
 * `command`; secret-catalog.ts CLASSIFY_PARAM_KEYS) are where its paths are?
 * True for an EXACT entry in the session's spec and for Mandu's own inspect
 * and policy tools (their inputs are symbols and questions, never a path
 * the tool opens). False for everything else, including a Claude Code
 * `mcp__*` tool that only matches the generic MCP fallback and OpenClaw's
 * dispatcher (`tool_call`, unmapped on purpose; the proxy sends the inner
 * tool's input as its params, dispatch.ts): for those the
 * derivation scans every string in the input (secret-catalog.ts
 * labelForUnmappedInput; confidentiality-plan-10 §11.11).
 */
export function inboundSpecNamesInput(toolName: string, sessionKey?: string, specs: SessionSpecLookup = processSessionSpecs): boolean {
  const specId = resolveInboundSpecId(sessionKey, specs);
  if (getCurrentPolicy().inbound[specId][toolName] !== undefined) return true;
  return isManduInspectTool(toolName) || isManduPolicyTool(toolName);
}

/** Session-health helper (dashboard.md §4.21): which advertised tool names
 *  have NO inbound spec for this session — their outputs will fail closed
 *  (symbolized whole). Pure over the same resolution `getToolInboundSpec`
 *  performs, so the answer is exactly what ingress will do. */
export function unknownToolNames(names: readonly string[], sessionKey?: string, specs: SessionSpecLookup = processSessionSpecs): string[] {
  const out: string[] = [];
  for (const n of names) {
    if (typeof n !== "string" || n === "") continue;
    if (!getToolInboundSpec(n, sessionKey, specs) && !out.includes(n)) out.push(n);
  }
  return out;
}
