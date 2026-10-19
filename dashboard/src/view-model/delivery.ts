/**
 * view-model/delivery — the §4.2c delivery-zone DEEP reveal: resolve the
 * DELIVERED reply's symbols to their full-fidelity originals via the arbiter.
 *
 * Mandu-new (no reference origin). WHY this exists: each event carries only
 * ONE level of symbol value (what its emitter saw at mint time). Under the fs
 * dual-view chokepoint the final reply's symbol is a NESTED chain — the
 * proxy-minted Read symbol's value is the AgentView twin's on-disk content,
 * itself a `$MDU:*` token minted by fs-sync BEFORE the session's first
 * event — so the inner symbol's original exists ONLY in the arbiter symbol
 * table, and a one-level, event-mined substitution shows the human a literal
 * symbol token in the "Agent Response" card. The server therefore asks the
 * arbiter (the `desymbolize` op — deep/fixpoint, the same egress the
 * reply-filter chokepoint applies) for each symbol the delivered reply
 * references, and ships the resolved originals in the final response step's
 * band (`DualResponseStep.symbols`).
 *
 * UTILITY-ONLY posture (reply-filter's): a failed or unavailable resolve
 * degrades to the event-mined value — symbols stay opaque, nothing can leak,
 * and this never throws. Only the FINAL response step is touched: interim
 * AgentView response cards keep rendering symbols as opaque tokens (that is
 * the defense working, not a display gap).
 *
 * FOREIGN-ARBITER sessions (found live, claude-e2e-chain-fetch-write-read
 * 2026-07-16): a docker/CI e2e run boots its own in-container arbiter and
 * shares only the EVENT dir with the host (test-docker.ts), so its symbols
 * die with the container and the dashboard's arbiter answers `desymbolize`
 * with the text unchanged — the reveal degraded to the one-level event value
 * and showed the human the NESTED inner token. But the session's own bands
 * often carry the inner value already (the mint event banded it on its tool
 * step), so before giving up we collapse the chain LOCALLY: fixpoint-
 * substitute the band-mined name→value table into the candidate. Unknown
 * tokens stay tokens (fail toward symbolic), and no new data is exposed —
 * every mined value ships to the browser in the same bundle regardless.
 */

import type { DualLanesModel } from "./dual-lanes.js";

/** Deep symbol resolver (EventSource.desymbolize): text in, text with every
 *  known symbol reference replaced by its original (fixpoint) out. */
export type Desymbolizer = (text: string) => Promise<string>;

/** Non-global copy of the symbol-token surface (dual-lanes' SYM_TOKEN_RE); a
 *  /g regex is stateful under .test() and unsafe to share across calls. */
const SYM_TOKEN_RE = /\$MDU:\w+\[\w+\](?:\.\w+)*/;
/** Global twin for String.replace (which resets lastIndex per call — safe). */
const SYM_TOKEN_RE_G = /\$MDU:\w+\[\w+\](?:\.\w+)*/g;

/** Mine the session's event-carried symbol values from every band the dual
 *  model already renders (tool up/down bands, response bands) — the LOCAL
 *  fallback table for collapsing nested chains when the arbiter cannot. */
function mineLocalValues(dual: DualLanesModel): Map<string, string> {
  const table = new Map<string, string>();
  for (const step of dual.steps) {
    const bands =
      step.step === "tool" ? [...step.upSyms, ...step.downSyms]
      : step.step === "response" ? step.symbols
      : [];
    for (const s of bands) if (s.value !== null && !table.has(s.name)) table.set(s.name, s.value);
  }
  return table;
}

/** Fixpoint-substitute the local table into `text`. Bounded (a pathological
 *  self-referential value must not spin); tokens the table doesn't know stay
 *  tokens — fail toward symbolic, never fabricate. */
function collapseLocally(text: string, table: Map<string, string>): string {
  let current = text;
  for (let i = 0; i < 8; i++) {
    const next = current.replace(SYM_TOKEN_RE_G, (m) => table.get(m) ?? m);
    if (next === current) break;
    current = next;
  }
  return current;
}

/**
 * Deep-resolve the delivered reply's band symbols in place. For each symbol
 * the FINAL response step references whose event-mined value is missing or
 * still symbol-bearing (a nested chain), ask the arbiter to desymbolize the
 * NAME itself — the text form handles field-path suffixes (`…[ab12].notes.md`)
 * the exact-name `resolve` op would miss. A reply that comes back unchanged
 * means the arbiter doesn't know the symbol (a foreign-arbiter session:
 * docker/CI e2e); then — and when the arbiter's answer itself still carries
 * tokens it doesn't know — collapse the nested chain from the session's OWN
 * bands (mineLocalValues) before keeping the event value (fail toward
 * symbolic — never fabricate an original). The desymbolizer is optional so
 * arbiter-less sources still get the local collapse. Returns how many band
 * values were deepened, for the caller's log line.
 */
export async function revealDeliveredReply(
  dual: DualLanesModel,
  desymbolize?: Desymbolizer,
): Promise<number> {
  let revealed = 0;
  let local: Map<string, string> | null = null; // mined lazily, once
  for (const step of dual.steps) {
    if (step.step !== "response" || !step.final) continue;
    for (const sym of step.symbols) {
      // Already full-fidelity: a flat (token-free) value needs no round-trip.
      if (sym.value !== null && !SYM_TOKEN_RE.test(sym.value)) continue;
      let next: string | null = null;
      try {
        const resolved = desymbolize ? await desymbolize(sym.name) : sym.name;
        if (resolved !== sym.name) next = resolved;
      } catch {
        /* fall through to the local table — display fidelity only */
      }
      if (next === null || SYM_TOKEN_RE.test(next)) {
        local ??= mineLocalValues(dual);
        const candidate = collapseLocally(next ?? sym.value ?? sym.name, local);
        // A candidate that is still just the bare name resolved nothing.
        if (candidate !== sym.name) next = candidate;
      }
      if (next !== null && next !== sym.value) {
        sym.value = next;
        revealed++;
      }
    }
  }
  return revealed;
}
