/**
 * regex — the linear-time regex engine of the pattern packs
 * (confidentiality-plan-15-prompt-filter.md §4.2). Mandu-new (no reference
 * origin).
 *
 * A pack's regex runs under RE2 semantics (re2js, a pure-JavaScript port of
 * RE2: no backreferences, no lookaround, matching linear in the text), so a
 * pack cannot stall the arbiter with catastrophic backtracking. A pattern the
 * engine rejects fails the pack's validation. Offsets are UTF-16 code units,
 * the unit every prompt-filter span uses.
 */
import { RE2JS } from "re2js";

/** The longest regex a pack may hold (characters). */
export const MAX_REGEX_LEN = 2000;
/** Matches reported per pattern per text: a pattern that matches everything
 *  stops here rather than build a million findings. */
export const MAX_MATCHES = 256;

export interface CompiledRegex {
  readonly source: string;
  /** Every non-overlapping, non-empty match, at most {@link MAX_MATCHES}. */
  matches(text: string): Array<{ start: number; end: number }>;
}

/** Compile `source`, or say why the engine refuses it. */
export function compileRegex(source: unknown): CompiledRegex | string {
  if (typeof source !== "string" || source === "") return "regex must be a non-empty string";
  if (source.length > MAX_REGEX_LEN) return `regex is longer than ${MAX_REGEX_LEN} characters`;
  let re: RE2JS;
  try {
    re = RE2JS.compile(source);
  } catch (err) {
    return `the RE2 engine rejects the regex: ${String((err as Error)?.message ?? err).split("\n")[0]}`;
  }
  return {
    source,
    matches(text: string) {
      const out: Array<{ start: number; end: number }> = [];
      const m = re.matcher(text);
      while (out.length < MAX_MATCHES && m.find()) {
        const start = m.start();
        const end = m.end();
        // An empty match finds nothing to hide.
        if (end > start) out.push({ start, end });
      }
      return out;
    },
  };
}
