/**
 * policy-snapshot — serialize the ACTIVE data-trust + data-usage policy into a
 * JSON-friendly, human-readable rule table.
 *
 * WHY (docs/design/ui/dashboard.md, per-tool-call policy modal): the dashboard
 * shows, for each tool call, BOTH the per-call decision (already on the wire in
 * EventPolicy) AND the governing RULE the tool falls under. The rule lives
 * arbiter-side (claude-code-inbound.ts inbound schema + tool-outbound.ts
 * resolve/egress maps + the engine's origin categories) and is not otherwise on
 * the wire. This module renders that rule once per session so the dashboard can
 * join it by tool name — a single source of truth that reflects the live YAML
 * config, instead of a static dashboard mirror that would DRIFT from what the
 * arbiter actually enforces.
 *
 * OBSERVABILITY ONLY: nothing here decides anything. It MIRRORS the same spec
 * objects classify()/desymbolizationDecision() read, so it cannot diverge from
 * enforcement. `describePolicySnapshot` is PURE (explicit inputs → snapshot) for
 * deterministic testing; `snapshotActivePolicy` reads the live active maps + an
 * engine's registered categories.
 */

import {
  isLiteralTrust,
  isKeySpec,
  isDataSpec,
  isActionSpec,
  isItemsSchema,
  isObjectSchema,
  type SchemaNode,
  type FieldMarker,
  type ToolSpec,
} from "./schema-types.js";
import type { ListMode } from "./trust-category.js";
import {
  getActiveInboundSpec,
  getActiveInboundSpecId,
} from "./tool-inbound.js";
import {
  MCP_TOOL_PREFIX,
  MCP_INBOUND_SPEC,
  MANDU_INSPECT_TOOL,
} from "./claude-code-inbound.js";
import {
  getActiveOutboundResolve,
  getActiveOutboundFieldPolicy,
  type InputFieldPolicy,
} from "./tool-outbound.js";

export type Trust = "TRUSTED" | "UNTRUSTED";

/** Per-leaf trust as rendered for display. "conditional" = a DataSpec whose
 * trust depends on its origin key (e.g. URL-keyed → UNTRUSTED unless trusted). */
export type FieldTrust = Trust | "conditional";

/** Origin category descriptor (URL / CHANNEL / DIR). The actual list entries
 * are intentionally NOT exposed (the security-critical TrustCategory only
 * surfaces mode + size); mode + size + the derived default convey the rule. */
export interface OriginRuleInput {
  id: string;
  mode: ListMode;
  listSize: number;
}

export interface OriginRule extends OriginRuleInput {
  /** allowlist → UNTRUSTED default; blocklist → TRUSTED default. */
  defaultTrust: Trust;
}

export interface InboundFieldRule {
  /** Dotted field path; "(result)" for a whole-result literal/marker.
   * Action branches are prefixed `<actionField>=<value>:`. */
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
  policy: InputFieldPolicy;
}

export interface OutboundRule {
  /** Tool-level resolve flag: true → resolve to raw (HumanView destination). */
  toolResolve: boolean;
  destination: "HumanView" | "AgentView";
  summary: string;
  fields: OutboundFieldRule[];
}

export interface ToolRule {
  tool: string;
  /** null when the tool has no inbound spec → caller fails closed to UNTRUSTED. */
  inbound: InboundRule | null;
  outbound: OutboundRule;
}

export interface PolicyRuleSnapshot {
  /** Active inbound spec id (e.g. "claude-code"). */
  specId: string;
  origins: OriginRule[];
  tools: Record<string, ToolRule>;
  /** The trust applied to any tool/field not described here (fail-closed). */
  fallbackTrust: "UNTRUSTED";
  /** Prefix that routes any matching tool to the synthetic `<prefix>*` rule. */
  mcpPrefix: string;
}

export interface PolicySnapshotInputs {
  specId: string;
  inboundSpec: Record<string, ToolSpec>;
  mcpPrefix: string;
  mcpSpec: ToolSpec;
  outboundResolve: Record<string, boolean>;
  outboundFieldPolicy: Record<string, Record<string, InputFieldPolicy>>;
  origins: OriginRuleInput[];
}

function defaultTrustFor(mode: ListMode): Trust {
  return mode === "allowlist" ? "UNTRUSTED" : "TRUSTED";
}

/** Render a single leaf marker for display. */
function describeMarker(marker: FieldMarker): Omit<InboundFieldRule, "field"> {
  if (isLiteralTrust(marker)) {
    return { trust: marker, category: null, detail: `${marker} (literal)` };
  }
  if (isKeySpec(marker)) {
    return {
      trust: "TRUSTED",
      category: marker.category,
      detail: `${marker.category} key (raw, always TRUSTED)`,
    };
  }
  if (isDataSpec(marker)) {
    return {
      trust: "conditional",
      category: marker.category,
      detail: `${marker.category}-keyed off ${marker.keyField} → UNTRUSTED unless ${marker.category} trusted`,
    };
  }
  // Unreachable (FieldMarker is closed) — fail-closed for display.
  return { trust: "UNTRUSTED", category: null, detail: "unknown marker (fail-closed)" };
}

/** Flatten a schema tree into a list of leaf field rules. Object keys join with
 * ".", `__items` arrays append "[]". A whole-result marker uses `base` or
 * "(result)". */
function flattenSchema(node: SchemaNode, base: string): InboundFieldRule[] {
  const path = base || "(result)";
  if (isLiteralTrust(node) || isKeySpec(node) || isDataSpec(node)) {
    return [{ field: path, ...describeMarker(node as FieldMarker) }];
  }
  if (isItemsSchema(node)) {
    return flattenSchema(node.__items, `${base}[]`);
  }
  if (isObjectSchema(node)) {
    const out: InboundFieldRule[] = [];
    for (const [key, child] of Object.entries(node)) {
      const childPath = base ? `${base}.${key}` : key;
      out.push(...flattenSchema(child as SchemaNode, childPath));
    }
    return out;
  }
  return [{ field: path, trust: "UNTRUSTED", category: null, detail: "unrecognized schema node (fail-closed)" }];
}

function summarizeStructured(fields: InboundFieldRule[]): string {
  let trusted = 0, conditional = 0, untrusted = 0;
  for (const f of fields) {
    if (f.trust === "TRUSTED") trusted++;
    else if (f.trust === "conditional") conditional++;
    else untrusted++;
  }
  return `${fields.length} fields — ${trusted} trusted, ${conditional} conditional, ${untrusted} untrusted`;
}

function describeInbound(spec: ToolSpec): InboundRule {
  if (isActionSpec(spec)) {
    const fields: InboundFieldRule[] = [];
    for (const [action, branch] of Object.entries(spec.schemas)) {
      for (const leaf of flattenSchema(branch, "")) {
        fields.push({ ...leaf, field: `${spec.actionField}=${action}: ${leaf.field}` });
      }
    }
    if (spec.defaultSchema !== undefined) {
      for (const leaf of flattenSchema(spec.defaultSchema, "")) {
        fields.push({ ...leaf, field: `${spec.actionField}=*: ${leaf.field}` });
      }
    }
    const branchCount = Object.keys(spec.schemas).length;
    const hasDefault = spec.defaultSchema !== undefined;
    return {
      kind: "action",
      summary: `dispatches on params.${spec.actionField}: ${branchCount} branch${branchCount === 1 ? "" : "es"}${hasDefault ? " + fail-closed default" : ""}`,
      fields,
    };
  }
  // Single-shape spec.
  const fields = flattenSchema(spec.schema, "");
  if (isLiteralTrust(spec.schema)) {
    return { kind: "literal", summary: `whole result: ${spec.schema}`, fields };
  }
  // Explicit whole-result rule on a structured spec (schema-types.ts
  // ToolInboundSpec.wholeResult): classify() applies it to a field-less
  // (flattened whole-result) request — the live proxy call shape — so the
  // modal must show it or it would claim fail-closed for a rule that grants.
  if (spec.wholeResult !== undefined) {
    const marker = describeMarker(spec.wholeResult);
    fields.unshift({
      field: "(result)",
      ...marker,
      detail: `${marker.detail} — whole-result rule`,
    });
  }
  return { kind: "structured", summary: summarizeStructured(fields), fields };
}

function describeOutbound(
  tool: string,
  outboundResolve: Record<string, boolean>,
  outboundFieldPolicy: Record<string, Record<string, InputFieldPolicy>>,
): OutboundRule {
  const toolResolve = outboundResolve[tool] === true;
  const destination = toolResolve ? "HumanView" : "AgentView";
  const fieldMap = outboundFieldPolicy[tool] ?? {};
  const fields: OutboundFieldRule[] = Object.entries(fieldMap).map(([field, policy]) => ({ field, policy }));
  const summary =
    `tool-level ${toolResolve ? "resolve (HumanView)" : "not_resolve (AgentView)"}` +
    (fields.length ? `; ${fields.length} field override${fields.length === 1 ? "" : "s"}` : "");
  return { toolResolve, destination, summary, fields };
}

/** Build the snapshot from explicit inputs (pure — for testing + reuse). */
export function describePolicySnapshot(inputs: PolicySnapshotInputs): PolicyRuleSnapshot {
  const origins: OriginRule[] = inputs.origins.map((o) => ({
    ...o,
    defaultTrust: defaultTrustFor(o.mode),
  }));

  // Tool universe: every tool named by either policy, plus the synthetic MCP
  // prefix rule so the dashboard can match `mcp__server__tool` by prefix.
  const toolNames = new Set<string>([
    ...Object.keys(inputs.inboundSpec),
    ...Object.keys(inputs.outboundResolve),
    ...Object.keys(inputs.outboundFieldPolicy),
  ]);

  const tools: Record<string, ToolRule> = {};
  for (const tool of toolNames) {
    const spec = inputs.inboundSpec[tool];
    tools[tool] = {
      tool,
      inbound: spec ? describeInbound(spec) : null,
      outbound: describeOutbound(tool, inputs.outboundResolve, inputs.outboundFieldPolicy),
    };
  }

  const mcpTool = `${inputs.mcpPrefix}*`;
  tools[mcpTool] = {
    tool: mcpTool,
    inbound: describeInbound(inputs.mcpSpec),
    outbound: describeOutbound(mcpTool, inputs.outboundResolve, inputs.outboundFieldPolicy),
  };

  // The Mandu inspect tool's HYBRID rule (exact name AND pure-symbolic result
  // shape → TRUSTED; anything else UNTRUSTED — claude-code-inbound.ts
  // classifyManduInspectResult) is enforced by classify() OUTSIDE the spec
  // map, so mirror it here explicitly or the dashboard's policy modal would
  // show the generic mcp__* rule for a call classify() actually trusted. The
  // gating mirrors enforcement exactly: claude-code spec only, and an explicit
  // exact-name entry in the inbound spec wins (that entry is already rendered
  // by the loop above, and this synthetic rule is then NOT added).
  if (inputs.specId === "claude-code" && inputs.inboundSpec[MANDU_INSPECT_TOOL] === undefined) {
    tools[MANDU_INSPECT_TOOL] = {
      tool: MANDU_INSPECT_TOOL,
      inbound: {
        kind: "literal",
        summary: "whole result: TRUSTED iff pure-symbolic (hybrid exact-name + shape rule)",
        fields: [
          {
            field: "(result)",
            trust: "conditional",
            category: null,
            detail:
              "TRUSTED iff the content is nothing but $MDU:* token(s) in the inspect " +
              "success envelope; error strings / any other content fail closed UNTRUSTED",
          },
        ],
      },
      outbound: describeOutbound(
        MANDU_INSPECT_TOOL,
        inputs.outboundResolve,
        inputs.outboundFieldPolicy,
      ),
    };
  }

  // NOT mirrored: the harness token-budget reminder rule (claude-code-inbound.ts
  // isHarnessTokenBudgetReminder — a whole result that is NOTHING but
  // `<system-reminder><total_tokens>N tokens left</total_tokens></system-reminder>`
  // block(s) classifies TRUSTED under ANY tool). It is span-SHAPE-keyed, not
  // tool-keyed, so it has no honest home in this per-tool map (a synthetic "*"
  // row would never resolve through ruleForTool and a per-tool row would
  // overclaim). The modal therefore shows the per-tool rule for such a result;
  // the classify reason string carries the actual verdict.
  //
  // Likewise NOT mirrored: `Read`'s two span-shape refinements
  // (claude-code-inbound.ts isPureSymbolicReadRendering / isReadHarnessNotice —
  // a whole-file twin's rendering made of nothing but arbiter-minted names, and
  // Claude Code's fixed "file unchanged / empty" notices). The Read row keeps
  // showing its fail-closed whole-result rule, which is what every Read
  // carrying a file byte still gets.
  return {
    specId: inputs.specId,
    origins,
    tools,
    fallbackTrust: "UNTRUSTED",
    mcpPrefix: inputs.mcpPrefix,
  };
}

/** Minimal view of the engine's category registry the snapshot needs. */
export interface CategoryRegistry {
  list(): { id: string; mode: ListMode; listSize: number }[];
}

/** Build a snapshot from the live ACTIVE inbound/outbound maps + an engine's
 * registered origin categories. */
export function snapshotActivePolicy(categories: CategoryRegistry): PolicyRuleSnapshot {
  return describePolicySnapshot({
    specId: getActiveInboundSpecId(),
    inboundSpec: getActiveInboundSpec(),
    mcpPrefix: MCP_TOOL_PREFIX,
    mcpSpec: MCP_INBOUND_SPEC,
    outboundResolve: getActiveOutboundResolve(),
    outboundFieldPolicy: getActiveOutboundFieldPolicy(),
    origins: categories.list().map((c) => ({ id: c.id, mode: c.mode, listSize: c.listSize })),
  });
}
