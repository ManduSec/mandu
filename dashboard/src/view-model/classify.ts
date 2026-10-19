/**
 * view-model/classify — §2.5/§4.4 T-LLM vs U-LLM model-family classification.
 *
 * Extracted verbatim from view-model.ts (agent-legibility split, behavior-preserving).
 * A low-level classification primitive: `lanes`, `call-detail`, and the timeline
 * all key colour + lane off `modelFamily`, so it lives in its own leaf module with
 * no dependency other than the event model.
 */

import type { ManduEvent } from "../event-model.js";

export type ModelFamily = "T-LLM" | "U-LLM" | null;

/**
 * T-LLM vs U-LLM is `kind` + `view` (§2.5). tllm_call always runs under
 * AgentView; ullm_call always under Quarantine. Returns null for non-model
 * events. The renderer keys color + lane off this so the two families are never
 * confusable (§4.4).
 */
export function modelFamily(event: ManduEvent): ModelFamily {
  if (event.kind === "tllm_call") return "T-LLM";
  if (event.kind === "ullm_call") return "U-LLM";
  return null;
}

export function isTllm(event: ManduEvent): boolean {
  return modelFamily(event) === "T-LLM";
}
export function isUllm(event: ManduEvent): boolean {
  return modelFamily(event) === "U-LLM";
}
