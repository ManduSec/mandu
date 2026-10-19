/**
 * key-shapes-filter — the `key-shapes` built-in filter
 * (confidentiality-plan-15-prompt-filter.md §4.1, phase 2). Mandu-new (no
 * reference origin).
 *
 * Known credential formats, with the same rules and checks the history and
 * workspace scans use (`secret-detectors.ts`: provider keys with their
 * prefixes and GitHub's checksum, private-key blocks, URL passwords,
 * credential assignments with entropy), located by offset
 * (`locateSecretShapes`). Category `secret.shape.<shape>`
 * (`secret.shape.github-token`, `secret.shape.private-key`, ...). Off by
 * default: a key Mandu does not know reaches the model unless this filter or
 * a pack is on (§9).
 */
import { locateSecretShapes } from "../policy/secret-detectors.js";
import type { FilterContext, PromptFilter, ScanResult } from "./filter.js";
import { KEY_SHAPES_ID } from "./policy.js";

export const KEY_SHAPE_CATEGORY = "secret.shape";

export class KeyShapesFilter implements PromptFilter {
  readonly id = KEY_SHAPES_ID;
  readonly cost = "inline" as const;
  readonly categories = [KEY_SHAPE_CATEGORY];

  scan(text: string, _ctx: FilterContext): ScanResult {
    return {
      findings: locateSecretShapes(text).map((s) => ({
        start: s.start, end: s.end, category: `${KEY_SHAPE_CATEGORY}.${s.shape}`, rule: s.shape, level: "no-model" as const,
      })),
      skipped: 0,
    };
  }
}
