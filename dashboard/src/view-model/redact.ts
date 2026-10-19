/**
 * view-model/redact — the signed-out projection of a session's events
 * (dashboard.md §6, "Reads and the admin session"). Mandu-new.
 *
 * WHAT IS LEFT. What the AI saw (the AgentView): each payload's `symbolized`
 * form, its symbols' names, origins and levels, the decisions, the paths,
 * the counts. The agent already holds all of it, so a program the agent runs
 * learns nothing new from it.
 *
 * WHAT GOES. Every value the AI did not see: a payload's `original` (the raw
 * tool output before masking, the request with the real value filled in, the
 * reply the human saw), a symbol's resolved `value`, the content of a seeded
 * file, the HumanView files of a session's final state, and the leak check's
 * `invariant.detail` (it quotes the text it found; the flag stays). Each becomes
 * `null` (a seeded file's content `""`) with `withheld: true` where the page
 * draws it, so a page can say "sign in to see it" rather than "not recorded".
 *
 * Two slots are not trusted, for logs written before 2026-10-06 (the
 * emitters now record only what the AI saw there):
 *   - a `symbolize` event's INPUT is the value before masking, recorded in
 *     both forms (`symbolized` too): it becomes the symbol the event's
 *     output records, the form the AI got;
 *   - a reply-filter `desymbolize` event recorded the whole terminal write
 *     or json-mode record as its `symbolized` form, which can hold text the
 *     AI never saw (a tool's output as the agent process got it, the
 *     human's prompt before the prompt filter): it keeps only the
 *     placeholders that text named.
 *
 * Pure; the input is never mutated (events are shared with caches).
 */

import type { DualRepr, ManduEvent } from "../event-model.js";

/** A `$MDU:` placeholder, as agent-page.ts reads them (names only). */
const TOKEN_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]*)*/g;

function redactDual(d: DualRepr | null): DualRepr | null {
  if (!d) return d;
  // The placeholders the original held as written: names the AI already has,
  // kept so both views can tell an echo (Mandu's refusal naming the token the
  // AI sent) from a kept value (held-tokens.ts). Never a value.
  const tokens = typeof d.original === "string" ? [...new Set(d.original.match(TOKEN_RE) ?? [])] : [];
  return {
    ...d,
    original: null,
    symbols: Array.isArray(d.symbols) ? d.symbols.map((s) => ({ ...s, value: null })) : d.symbols,
    ...(tokens.length ? { originalTokens: tokens } : {}),
  };
}

/** The placeholders `d.symbolized` named, and nothing around them. */
function namesOnly(d: DualRepr | null): DualRepr | null {
  if (!d) return d;
  const names = typeof d.symbolized === "string" ? [...new Set(d.symbolized.match(TOKEN_RE) ?? [])] : [];
  return { ...d, symbolized: names.join(" ") };
}

/** A `symbolize` event's input as the AI got it: the symbol it became. */
function redactSymbolizeInput(e: ManduEvent): DualRepr | null {
  if (!e.input) return e.input;
  const symbol = typeof e.output?.symbolized === "string" ? e.output.symbolized : "";
  return { symbolized: symbol, original: null, differs: true, symbols: [] };
}

/** One event as a signed-out viewer may see it. */
export function redactEvent(e: ManduEvent): ManduEvent {
  const frame = e.kind === "desymbolize" && e.emitter === "reply-filter";
  const input = e.kind === "symbolize" ? redactSymbolizeInput(e) : redactDual(frame ? namesOnly(e.input) : e.input);
  const output = redactDual(frame ? namesOnly(e.output) : e.output);
  const out: ManduEvent = { ...e, input, output };
  // The leak check's detail quotes the text it found in the request (the
  // proxies' `invariantDetail`: up to 120 characters of the span that
  // survived its mask, which can be a secret's value). Signed out, the flag
  // stays and the quote goes (dashboard.md §4.25ae).
  if (e.invariant && typeof e.invariant.detail === "string") out.invariant = { violatedInvariant: e.invariant.violatedInvariant };
  if (Array.isArray(e.seedFiles)) {
    out.seedFiles = e.seedFiles.map((f) => ({ ...f, content: "", withheld: true as const }));
  }
  if (Array.isArray(e.finalViews)) {
    out.finalViews = e.finalViews.map((v) =>
      v.view === "AgentView"
        ? v
        : { ...v, files: v.files.map((f) => ({ ...f, content: null, withheld: true as const })) },
    );
  }
  return out;
}

export function redactEvents(events: readonly ManduEvent[]): ManduEvent[] {
  return events.map(redactEvent);
}
