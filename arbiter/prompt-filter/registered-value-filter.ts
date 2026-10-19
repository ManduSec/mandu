/**
 * registered-value-filter — the default prompt filter
 * (confidentiality-plan-15-prompt-filter.md §4.1). Mandu-new (no reference
 * origin).
 *
 * A finding is a span equal to a registered secret's value, or to a long line
 * of a multi-line one: the patterns the value backstop has always used
 * (`secretValueMatch`), now with offsets. It matches only values Mandu already
 * protects, so it cannot misfire on unrelated text, and the value already has
 * a symbol, so a mask stores nothing new (decision 2).
 *
 * THE PROMPT FLOOR. In a `human` segment a value shorter than
 * {@link PROMPT_FLOOR_MIN_LEN} characters, or whose Shannon entropy is under
 * {@link PROMPT_FLOOR_MIN_ENTROPY} bits per character, is skipped (the
 * `credential-assignment` gate of secret-detectors.ts): a registered
 * `DB_PASSWORD=postgres` must not mask the word "postgres" the human typed.
 * Skipped values are COUNTED, never named. `harness` and `side-call`
 * segments get no prompt floor: they are ingress of data the human did not
 * write, and the general floors (MIN_FINGERPRINT_LEN, the line floor) are all
 * that applies there, as on the tool-result path (§3.1).
 */

import type { ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { entropy } from "../policy/secret-detectors.js";
import type { FilterContext, Finding, PromptFilter, ScanResult } from "./filter.js";
import type { RegisteredValueIndex } from "./registered-values.js";

/** The prompt floor's length (characters). */
export const PROMPT_FLOOR_MIN_LEN = 12;
/** The prompt floor's entropy (bits per character). */
export const PROMPT_FLOOR_MIN_ENTROPY = 3.0;

export const REGISTERED_VALUE_FILTER_ID = "registered-value";
export const REGISTERED_VALUE_CATEGORY = "secret.registered";

/** Does the prompt floor let `matched` through a human segment unmasked? */
export function belowPromptFloor(matched: string): boolean {
  return matched.length < PROMPT_FLOOR_MIN_LEN || entropy(matched) < PROMPT_FLOOR_MIN_ENTROPY;
}

export interface RegisteredValueFilterDeps {
  /** The index, synced to the symbol table. */
  index: () => RegisteredValueIndex;
  /** The row's level when the row still counts (active, secret, and the
   *  backstop's evidence rules hold), else null. Read live per hit. */
  rowLevel: (symbol: string) => ConfidentialityLevel | null;
}

export class RegisteredValueFilter implements PromptFilter {
  readonly id = REGISTERED_VALUE_FILTER_ID;
  readonly cost = "inline" as const;

  constructor(private readonly deps: RegisteredValueFilterDeps) {}

  scan(text: string, ctx: FilterContext): ScanResult {
    const findings: Finding[] = [];
    const skipped = new Set<string>();
    const levels = new Map<string, ConfidentialityLevel | null>();
    for (const o of this.deps.index().occurrences(text)) {
      let level = levels.get(o.symbol);
      if (level === undefined) { level = this.deps.rowLevel(o.symbol); levels.set(o.symbol, level); }
      if (level === null) continue;
      if (ctx.origin === "human" && belowPromptFloor(o.text)) {
        skipped.add(o.text);
        continue;
      }
      findings.push({
        start: o.start, end: o.end, category: REGISTERED_VALUE_CATEGORY,
        level, symbol: o.symbol, how: o.how,
      });
    }
    return { findings, skipped: skipped.size };
  }
}
