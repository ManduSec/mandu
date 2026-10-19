/**
 * trusted-shape — a TEST-ONLY replica of the arbiter's pure-symbolic inspect
 * trust gate, used as a drift tripwire.
 *
 * Mandu (interceptors/openclaw-inspect-plugin) test helper.
 *
 * PROVENANCE: replicates arbiter/policy/claude-code-inbound.ts
 * `SYMBOL_TOKEN_RE` / `SYMBOL_ONLY_RE` / `SYMBOL_THEN_JSON_RE` /
 * `isInspectSuccessEnvelope` / `isPureSymbolicInspectResult` (2026-08-06).
 * Deliberately NOT imported from the arbiter package: (a) this package's
 * suite must run with no sibling packages resolvable, and (b) the arbiter's
 * policy files are under concurrent edit by the session that owns the
 * openclaw-agent inbound spec — a static import would couple this suite to
 * files it must not touch. If the arbiter grammar changes, update this
 * replica in the same change (the tests exist precisely to make result-shape
 * drift loud).
 *
 * next_step values are imported from the REAL inspect-mcp NEXT_STEP_BY_KIND —
 * the TCB author of those strings — so a drift between the plugin's envelope
 * and the map fails here even before the arbiter sees it.
 */

import { NEXT_STEP_BY_KIND } from "../../../inspect-mcp/src/inspect-symbol.js";
import type { PluginToolResult } from "../../src/openclaw-api.js";

const SYMBOL_TOKEN_RE =
  /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/;

export const SYMBOL_ONLY_RE = new RegExp(`^(?:${SYMBOL_TOKEN_RE.source})$`);

const SYMBOL_THEN_JSON_RE = new RegExp(`^(${SYMBOL_TOKEN_RE.source})\\s*(\\{[\\s\\S]*\\})$`);

const INSPECT_MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._/:-]{0,63}$/;

const INSPECT_CONTENT_KIND_RE =
  /^(?:as_requested|wrong_content|substantive|error_or_refusal|auth_wall|empty|unknown)$/;

function isInspectSuccessEnvelope(text: string): boolean {
  if (!text.startsWith("{")) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return false;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return false;
  const o = parsed as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length < 1 || keys.length > 4) return false;
  if (
    !keys.every(
      (k) => k === "result_symbol" || k === "model" || k === "content_kind" || k === "next_step",
    )
  ) {
    return false;
  }
  if (typeof o.result_symbol !== "string" || !SYMBOL_ONLY_RE.test(o.result_symbol)) return false;
  if (keys.includes("model") && (typeof o.model !== "string" || !INSPECT_MODEL_ID_RE.test(o.model))) {
    return false;
  }
  if (
    keys.includes("content_kind") &&
    (typeof o.content_kind !== "string" || !INSPECT_CONTENT_KIND_RE.test(o.content_kind))
  ) {
    return false;
  }
  if (keys.includes("next_step")) {
    if (typeof o.content_kind !== "string") return false;
    if (o.next_step !== NEXT_STEP_BY_KIND[o.content_kind as keyof typeof NEXT_STEP_BY_KIND]) {
      return false;
    }
  }
  return true;
}

/** The arbiter's whole-result pure-symbolic gate (replica — see header). */
export function isPureSymbolicInspectResult(value: string): boolean {
  if (typeof value !== "string") return false;
  const v = value.trim();
  if (v === "") return false;
  if (SYMBOL_ONLY_RE.test(v)) return true;
  if (isInspectSuccessEnvelope(v)) return true;
  const m = v.match(SYMBOL_THEN_JSON_RE);
  return m !== null && isInspectSuccessEnvelope(m[2]!);
}

/** Flatten a plugin tool result the way the anthropic-proxy flattens a
 * tool_result's text blocks: joined WITHOUT a separator (see the
 * claude-code-inbound.ts SYMBOL_THEN_JSON_RE comment — that grammar exists
 * because flattenToolResultContent joins this way). */
export function flattenLikeProxy(result: PluginToolResult): string {
  return result.content.map((b) => b.text).join("");
}
