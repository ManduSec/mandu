/**
 * tool-overrides — apply YAML `tools:` overrides onto COPIES of the inbound
 * spec + outbound maps (pure).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/tool-overrides.ts
 *   Purpose: let a policy file override or add a per-tool inbound schema on top
 *   of TOOL_INBOUND_SPEC, so deployments can re-map tools (which is exactly what
 *   the Claude-Code re-map will use) without editing TypeScript.
 *
 *   Adaptation for Mandu — FLAGGED:
 *     - The OUTBOUND (data-usage) override branch is lifted back in: a policy
 *       file can re-map a tool's destination kind (HumanView vs Agent FS) per
 *       the data-usage policy. NOTE: a "resolve" outbound override only declares
 *       the destination kind — it does NOT auto-approve resolving an untrusted
 *       symbol; the egress gate still requires approval for symbol-as-command /
 *       untrusted-destination flows (fail-closed).
 *     - 2026-09-05 (policy-surface.md §2.2): the reference MUTATED the
 *       active module tables in place. This version is PURE: it takes the
 *       tables to start from and returns NEW tables, leaving the built-in
 *       constants untouched. `compiled-policy.ts` calls it on copies and
 *       freezes the result; the in-place `mergeToolOverrides` is gone.
 *
 *   YAML shape consumed here:
 *     tools:
 *       WebFetch:
 *         inbound:                 # overrides TOOL_INBOUND_SPEC.WebFetch.schema
 *           url: TRUSTED
 *           text: UNTRUSTED
 *         outbound:                # overrides the active outbound resolve/field
 *           url: resolve
 *       Read:
 *         outbound:
 *           file_path: not_resolve
 *       my_custom_tool:            # new tool — added to the maps
 *         inbound: UNTRUSTED
 *         outbound: resolve        # scalar form → tool-level resolve=true
 */

import type { SchemaNode, ToolSpec } from "./schema-types.js";
import { isActionSpec } from "./schema-types.js";
import type { InputFieldPolicy } from "./tool-outbound.js";

export type ToolInboundOverride = SchemaNode;

export type ToolOutboundOverride =
  | "resolve"
  | "not_resolve"
  | Record<string, InputFieldPolicy>;

export interface ToolPolicyEntry {
  inbound?: ToolInboundOverride;
  /** Outbound (egress / data-usage) override: a tool-level resolve flag
   * ("resolve" | "not_resolve") or a per-field policy map. See the provenance
   * note re: the gate still being fail-closed. */
  outbound?: ToolOutboundOverride;
}

interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
}

function isFieldPolicy(v: unknown): v is InputFieldPolicy {
  return v === "resolve" || v === "not_resolve" || v === "no_symbols_expected";
}

export interface ToolTables {
  inbound: Record<string, ToolSpec>;
  outboundResolve: Record<string, boolean>;
  outboundFieldPolicy: Record<string, Record<string, InputFieldPolicy>>;
}

/**
 * Apply `tools:` overrides to `base`, returning NEW tables (the inputs are not
 * modified). An inbound override REPLACES the tool's schema (keeping its
 * paramsKeys) and, by design, drops any `wholeResult` grant — an operator
 * override must not silently inherit a built-in trust grant. An outbound
 * override sets the tool-level resolve flag or a per-field policy map.
 */
export function applyToolOverrides(
  base: ToolTables,
  tools: Record<string, ToolPolicyEntry> | undefined,
  log: Logger,
): ToolTables {
  const inbound: Record<string, ToolSpec> = { ...base.inbound };
  const outboundResolve: Record<string, boolean> = { ...base.outboundResolve };
  const outboundFieldPolicy: Record<string, Record<string, InputFieldPolicy>> = {};
  for (const [tool, fields] of Object.entries(base.outboundFieldPolicy)) outboundFieldPolicy[tool] = { ...fields };
  if (!tools) return { inbound, outboundResolve, outboundFieldPolicy };

  for (const [toolName, entry] of Object.entries(tools)) {
    if (!toolName) {
      log.warn(`[Mandu-policy] skipping tool override with empty name`);
      continue;
    }
    if (entry == null || typeof entry !== "object") {
      log.warn(`[Mandu-policy] tool "${toolName}" override must be an object`);
      continue;
    }
    if (entry.inbound !== undefined) {
      const existing = inbound[toolName];
      if (existing && isActionSpec(existing)) {
        log.warn(
          `[Mandu-policy] tool "${toolName}" is action-dispatched; YAML override ` +
          `replaces the entire action map with a flat schema`,
        );
      }
      inbound[toolName] = {
        ...(existing && !isActionSpec(existing) && existing.paramsKeys ? { paramsKeys: existing.paramsKeys } : {}),
        schema: entry.inbound,
      };
      log.info(`[Mandu-policy] tool "${toolName}" inbound override registered`);
    }
    if (entry.outbound !== undefined) {
      const override = entry.outbound;
      if (override === "resolve" || override === "not_resolve") {
        outboundResolve[toolName] = override === "resolve";
        log.info(`[Mandu-policy] tool "${toolName}" outbound resolve=${override === "resolve"}`);
      } else if (typeof override !== "object" || override === null) {
        log.warn(`[Mandu-policy] tool "${toolName}" outbound must be "resolve" | "not_resolve" | object`);
      } else {
        const fields: Record<string, InputFieldPolicy> = { ...(outboundFieldPolicy[toolName] ?? {}) };
        let hasResolve = false;
        for (const [field, policy] of Object.entries(override)) {
          if (!isFieldPolicy(policy)) {
            log.warn(
              `[Mandu-policy] tool "${toolName}" field "${field}" has invalid policy ` +
              `"${String(policy)}" (expected resolve | not_resolve | no_symbols_expected)`,
            );
            continue;
          }
          fields[field] = policy;
          if (policy === "resolve") hasResolve = true;
        }
        outboundFieldPolicy[toolName] = fields;
        outboundResolve[toolName] = hasResolve;
        log.info(
          `[Mandu-policy] tool "${toolName}" outbound per-field override registered ` +
          `(${Object.keys(override).length} fields, tool-level resolve=${hasResolve})`,
        );
      }
    }
  }
  return { inbound, outboundResolve, outboundFieldPolicy };
}
