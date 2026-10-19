/**
 * view-model/held-tokens — which placeholders a tool result kept from the AI,
 * and which it only echoed (dashboard.md §4.2f, §4.25b "A refusal is not a
 * mask").
 *
 * Mandu-new (no reference origin). WHY: Mandu's fail-closed refusal names the
 * placeholder the AI put in its own call, so the result the AI got holds a
 * token although nothing in it was masked. The session page (agent-page.ts)
 * and the inspector's paired rows (paired-rows.ts) both decide "masked" with
 * this one rule, so the two views never disagree about the same step. Pure;
 * names only, never a value.
 */

import type { DualToolStep } from "./dual-lanes.js";

/** The `$MDU:` token grammar (field segments may contain dots). */
export const SYM_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]*)*/g;

/** A token grammar match swallows sentence punctuation (field segments may
 *  contain dots: `…content.` ending a sentence is the token plus a period).
 *  Same trim as lineage.ts's token mining. */
export function trailingDots(m: string): string {
  return /\.+$/.exec(m)?.[0] ?? "";
}

/** Each token in `text`, with the sentence punctuation it swallowed split off. */
export function tokensIn(text: string): { index: number; name: string; end: number }[] {
  return [...text.matchAll(SYM_RE)].map((m) => {
    const dots = trailingDots(m[0]);
    const name = dots ? m[0].slice(0, -dots.length) : m[0];
    return { index: m.index!, name, end: m.index! + name.length };
  });
}

type ResultFields = Pick<DualToolStep, "input" | "resultAgent" | "resultHuman" | "resultHumanTokens">;

/** The tokens a result kept from the AI: every token in what the AI got,
 *  but one the call itself sent that the tool's own result holds as written
 *  (Mandu's refusal naming the placeholder it withheld, a command printing
 *  its argument). That came back as the AI sent it, so nothing was kept
 *  from the AI by it. A token the tool's own result lacks (a reply that
 *  carried the real value, masked back to the same token) or the call never
 *  sent (a twin's placeholder) still counts (dashboard.md §4.25b). */
export function heldTokens(step: ResultFields): string[] {
  const got = tokensIn(step.resultAgent ?? "").map((m) => m.name);
  // Signed out the original is left out, its placeholders kept (redact.ts).
  const human = step.resultHuman ? tokensIn(step.resultHuman).map((m) => m.name) : step.resultHumanTokens ?? null;
  if (!got.length || !step.input || !human) return got;
  const sent = new Set(tokensIn(step.input).map((m) => m.name));
  const echoed = new Set(human.filter((n) => sent.has(n)));
  return got.filter((n) => !echoed.has(n));
}

/** The distinct tokens in what the AI got that it only echoed: the ones
 *  `heldTokens` leaves out. Empty when the result kept everything or held
 *  no token. */
export function echoedTokens(step: ResultFields): string[] {
  const held = new Set(heldTokens(step));
  return [...new Set(tokensIn(step.resultAgent ?? "").map((m) => m.name).filter((n) => !held.has(n)))];
}
