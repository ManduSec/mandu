/**
 * filter — the prompt filter's detector contract
 * (confidentiality-plan-15-prompt-filter.md §4). Mandu-new (no reference
 * origin).
 *
 * A filter only DETECTS: it reports spans and their category. What happens to
 * a finding is the policy's (§6, policy.ts): built-in filters
 * (`registered-value`, `key-shapes`) and pattern packs (packs.ts).
 */

import type { ConfidentialityLevel } from "../symbol-table/confidentiality.js";

/** Who wrote a segment of user-role text (§3.1). `tool` results are not
 *  segments: they keep the existing ingress path. */
export type SegmentOrigin = "human" | "harness" | "side-call";

export const SEGMENT_ORIGINS: readonly SegmentOrigin[] = ["human", "harness", "side-call"];

/** What the policy does with a finding (§7). Phase 2 enacts `pass`,
 *  `log`, `redact`, `mask` and `block`; `ask` (the Inbox hold) is phase 3. */
export type PromptAction = "pass" | "log" | "redact" | "mask" | "ask" | "block";

/** The strictest-wins order of §4 (`block` > `ask` > `mask` > `redact` >
 *  `log` > `pass`). */
export const ACTION_RANK: Readonly<Record<PromptAction, number>> = {
  pass: 0, log: 1, redact: 2, mask: 3, ask: 4, block: 5,
};

export interface FilterContext {
  origin: SegmentOrigin;
  /** A classifier plugin's `endpoint:` from the policy (§5): the name of the
   *  `models:` entry it may send the text to. */
  endpoint?: string;
}

/** One finding of one filter over one segment's text. */
export interface Finding {
  /** [start, end) in UTF-16 code units of the segment's text. */
  start: number;
  end: number;
  /** Dotted category: `secret.registered`, `secret.shape.github`, … */
  category: string;
  /** For `mask`: the level a minted symbol gets. */
  level?: ConfidentialityLevel;
  /** A registered value's own symbol (the registered-value filter). */
  symbol?: string;
  /** `value` (the whole registered value) or `line` (a long line of one). */
  how?: "value" | "line";
  /** Which rule found it: a pack's pattern id, `keyword`, a key shape. */
  rule?: string;
}

/** What one scan reports: findings, and how many registered values the
 *  prompt floor let through (counted, never named, §4.1). */
export interface ScanResult {
  findings: Finding[];
  skipped: number;
}

export interface PromptFilter {
  id: string;
  /** Latency class: `inline` runs in the arbiter's turn, `model` is a
   *  classifier (phase 3, an out-of-process plugin). */
  cost: "inline" | "model";
  /** The categories it may report (a dotted prefix covers its children):
   *  what decides its default `on_error` (§4.4). */
  categories?: readonly string[];
  /** A plugin (§4.3) scans several segments in one run: the engine calls
   *  this once per request with every segment it has no cached answer for.
   *  Rejects on failure (every segment of the batch fails alike). */
  scanMany?(segments: ReadonlyArray<{ id: string; origin: SegmentOrigin; text: string }>, ctx: Pick<FilterContext, "endpoint">): Promise<Map<string, ScanResult>>;
  /** Throws (or rejects) on failure: the engine applies the filter's
   *  `on_error`. Built-in filters and packs answer at once; an
   *  out-of-process plugin (§4.3, phase 3) answers a promise, so the engine
   *  awaits every scan. */
  scan(text: string, ctx: FilterContext): ScanResult | Promise<ScanResult>;
}
