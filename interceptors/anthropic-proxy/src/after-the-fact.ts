/**
 * after-the-fact — the `[mandu:secret] masked after the fact` note
 * (confidentiality.md §7.1, "Masked after the fact"; 2026-10-05).
 * Mandu-new (no reference origin). The openai-proxy keeps a byte-identical
 * copy (interceptors/openai-proxy/src/after-the-fact.ts).
 *
 * Every request re-sends the whole history, and the request rewrite
 * re-classifies every tool_result in it. Once a file is labelled (or a value
 * registered), a result the model already read in clear comes back masked in
 * the next request: right for the invariant, but the model then reads its
 * own earlier answer about the content beside a result that is now a symbol,
 * concludes it made that answer up, and apologises to the user for inventing
 * what it really read (live tour, 2026-10-05).
 *
 * The criterion is what THIS proxy forwarded: a result whose body went out
 * in clear in an earlier request (remembered by tool-call id once that
 * request's rewrite completed) and that is masked as a secret now gets one
 * more note line. The note is static text (plus, for Claude Code's Read, a
 * static sentence about the harness's "file unchanged" notice): it carries
 * no byte of the masked result, no path, no value. The mask stays.
 *
 * Kept in memory AND in the arbiter (utility, not security). A conversation
 * resumed under a new launch (`claude --resume`, `--continue`, `codex
 * resume`) re-sends its history to a proxy that never saw it, so the ids
 * also go to the arbiter's mandu.db (`recordForwardedClear`, human plane),
 * and the first request that names an id this proxy does not know asks the
 * arbiter about it (`forwardedClear`). The key is the tool-call id alone:
 * the provider mints it and a resume re-sends it byte for byte, while the
 * Mandu session key is per launch and the agent's own session id is not
 * promised either (Claude Code's `--fork-session` mints a new one). Ids
 * only, never a byte of the result. A failure of either op loses the note,
 * never the mask.
 *
 * Two launches at once (2026-10-17): an id the arbiter did not know at the
 * first ask is held as unknown, but another launch resumed on the same
 * conversation may forward that result in clear later. So each ask also
 * carries the arbiter's generation from the previous answer and gets back
 * the ids recorded since (`forwardedClear` with `since`), still one op per
 * request; an unknown id among them becomes known. With no unknown id held
 * and none to ask, no op at all.
 */

/** Bound on the remembered ids (a long session's tool calls); the oldest
 *  are forgotten first, which only drops a note, never a mask. */
const MAX_IDS = 100_000;

/** Ids per arbiter request (the arbiter takes at most 10 000). */
const STORE_CHUNK = 1_000;

/** Where the ids outlive this proxy: the arbiter (proxy.ts builds it over the
 *  `Arbiter`'s `forwardedClear` / `recordForwardedClear`). */
export interface ClearResultStore {
  /** The subset of `ids` recorded as forwarded in clear. */
  known(ids: string[]): Promise<string[]>;
  /** Record `ids` as forwarded in clear (idempotent). */
  record(ids: string[]): Promise<void>;
  /** `known` with the store's generation and, given an earlier answer's
   *  (`since`), the ids recorded after it ("Two launches at once"). Absent
   *  (an older arbiter): an id unknown at its first ask stays unknown. */
  knownSince?(ids: string[], since?: number): Promise<ClearResultAnswer>;
}

/** One `knownSince` answer (arbiter/ipc/protocol.ts ForwardedClearResult). */
export interface ClearResultAnswer {
  ids: string[];
  generation?: number;
  recent?: string[];
  recentComplete?: boolean;
}

/** The store over a proxy's arbiter (its `forwardedClear` and
 *  `recordForwardedClear`), or undefined when it lacks either: the ledger is
 *  then memory only. */
export function arbiterClearResultStore(arbiter: {
  forwardedClear?(ids: string[]): Promise<string[]>;
  recordForwardedClear?(ids: string[]): Promise<void>;
  forwardedClearSince?(ids: string[], since?: number): Promise<ClearResultAnswer>;
}): ClearResultStore | undefined {
  const known = arbiter.forwardedClear?.bind(arbiter);
  const record = arbiter.recordForwardedClear?.bind(arbiter);
  const knownSince = arbiter.forwardedClearSince?.bind(arbiter);
  return known && record ? { known, record, ...(knownSince ? { knownSince } : {}) } : undefined;
}

/** A tool-call id worth keeping: 1..256 printable ASCII, no space (the
 *  arbiter skips any other). Pure. */
function isCallId(id: unknown): id is string {
  return typeof id === "string" && id.length > 0 && id.length <= 256 && /^[\x21-\x7e]+$/.test(id);
}

/** Add to a bounded insertion-ordered set, dropping the oldest. */
function addBounded(set: Set<string>, id: string, max: number): void {
  if (set.has(id)) return;
  set.add(id);
  if (set.size > max) {
    const oldest = set.values().next().value;
    if (oldest !== undefined) set.delete(oldest);
  }
}

/** The tool-call ids whose result body this proxy (or, through the store, an
 *  earlier launch's) forwarded in clear. */
export class ClearResultLedger {
  private readonly ids = new Set<string>();
  /** Ids the store was asked about and did not know: not asked again. This
   *  proxy's `remember`, or (with `knownSince`) another launch's record seen
   *  in a later answer's `recent`, makes them known. */
  private readonly asked = new Set<string>();
  /** The store's generation at the last `knownSince` answer. */
  private generation: number | undefined;
  /** Ids remembered whose record has not reached the store yet. */
  private readonly unsaved = new Set<string>();
  private readonly store: ClearResultStore | undefined;
  private readonly log: (msg: string) => void;

  constructor(private readonly max = MAX_IDS, opts: { store?: ClearResultStore; log?: (msg: string) => void } = {}) {
    this.store = opts.store;
    this.log = opts.log ?? (() => {});
  }

  /** Before a request's rewrite: ask the store about the ids of its results
   *  this ledger does not know yet (a resumed history's). Never throws: a
   *  failed ask only means no note for those ids this time. */
  async prime(ids: Iterable<string>): Promise<void> {
    if (!this.store) return;
    const ask = [...new Set([...ids].filter((id) => isCallId(id) && !this.ids.has(id) && !this.asked.has(id)))];
    // "Two launches at once": while an id is held as unknown, the first ask
    // of each request also reads what was recorded since the last answer
    // (another launch's proxy may have forwarded that result in clear since).
    const since = this.store.knownSince && (ask.length > 0 || this.asked.size > 0);
    for (let i = 0; i < ask.length || (i === 0 && since); i += STORE_CHUNK) {
      const chunk = ask.slice(i, i + STORE_CHUNK);
      let known: string[];
      try {
        if (i === 0 && since) {
          const answer = await this.store.knownSince!(chunk, this.generation);
          this.learn(answer);
          known = answer.ids;
        } else {
          known = await this.store.known(chunk);
        }
      } catch (err) {
        this.log(`after-the-fact: the arbiter could not say which results went in clear before (${(err as Error).message}); no note for them this time (the mask stays)`);
        return;
      }
      const hit = new Set(Array.isArray(known) ? known : []);
      for (const id of chunk) {
        if (hit.has(id)) addBounded(this.ids, id, this.max);
        else addBounded(this.asked, id, this.max);
      }
    }
  }

  /** A `knownSince` answer's news: the ids held as unknown that were
   *  recorded since become known. A generation that went down (the store
   *  emptied or rebuilt), or a `recent` list cut short, cannot be read that
   *  way: every unknown id is forgotten, so the next request asks again. */
  private learn(answer: ClearResultAnswer): void {
    const g = typeof answer.generation === "number" && Number.isSafeInteger(answer.generation) ? answer.generation : undefined;
    if (g === undefined) return;
    if (this.generation !== undefined && (g < this.generation || (answer.recent !== undefined && answer.recentComplete === false))) {
      this.asked.clear();
    } else if (Array.isArray(answer.recent)) {
      for (const id of answer.recent) {
        if (typeof id === "string" && this.asked.has(id)) {
          this.asked.delete(id);
          addBounded(this.ids, id, this.max);
        }
      }
    }
    this.generation = g;
  }

  /** Record the ids of one completed rewrite (call AFTER it succeeded, so a
   *  refused request never counts as delivered). In memory at once; the
   *  returned promise settles once the new ones reached the store (never
   *  rejects: a failed record is retried with the next one). */
  remember(ids: Iterable<string>): Promise<void> {
    for (const id of ids) {
      if (!isCallId(id) || this.ids.has(id)) continue;
      addBounded(this.ids, id, this.max);
      this.asked.delete(id);
      if (this.store) addBounded(this.unsaved, id, this.max);
    }
    return this.flush();
  }

  private async flush(): Promise<void> {
    if (!this.store || this.unsaved.size === 0) return;
    const pending = [...this.unsaved];
    for (let i = 0; i < pending.length; i += STORE_CHUNK) {
      const chunk = pending.slice(i, i + STORE_CHUNK);
      try {
        await this.store.record(chunk);
      } catch (err) {
        this.log(`after-the-fact: could not record ${pending.length - i} clear result id(s) with the arbiter (${(err as Error).message}); retried with the next request`);
        return;
      }
      for (const id of chunk) this.unsaved.delete(id);
    }
  }

  /** Did an earlier request carry this result's body in clear? */
  wasClear(id: string): boolean {
    return this.ids.has(id);
  }
}

/** The note line (without the `[mandu:secret] ` marker). `taintCause`: the
 *  note's own `masked:` line above already says why (a process taint), so
 *  this line does not claim a label. `harnessRead`: Claude Code's Read, whose
 *  later call on an unchanged file answers with the harness's own notice,
 *  which the arbiter passes in clear (confidentiality.md §7.1, "The Read
 *  dedup notice"): the line tells the model that notice points back here.
 *
 *  Worded from the MODEL's side (live check 2026-10-05, Opus 5.5): the first
 *  wording said the result "reached you in clear in an earlier request", the
 *  model saw no earlier request, only this placeholder followed by its own
 *  reply quoting the content, and it told the user the reply was invented. A
 *  model has no notion of requests; it has the transcript. So the line says
 *  what changed in the transcript (Mandu rewrites the earlier results each
 *  time the conversation is sent) and points at Mandu's system note, which
 *  the model trusts more than text inside a tool result. */
export function afterTheFactLine(opts: { taintCause: boolean; harnessRead: boolean }): string {
  const why = opts.taintCause
    ? "Mandu masks it now for the reason above"
    : "it was marked secret after that (a lock or a label, possibly one made later in this conversation)";
  const read = opts.harnessRead
    ? " If you Read this file again while it is unchanged, Claude Code answers with its own \"file unchanged since your last Read\" notice, not the file: that notice points back to this result, which now shows only the symbol."
    : "";
  return `masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; ${why}, so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this.${read}`;
}

/** Marks the system note below (one per request, never duplicated). */
export const AFTER_THE_FACT_MARKER = "[mandu:after-the-fact]";

/**
 * Mandu's system note, sent while any result of the request carries the line
 * above. Static text (no id, no count, no result byte), so it is
 * byte-identical on every request that has it and the prompt cache breaks
 * only once, when the first result is masked after the fact. In the system
 * prompt because a model reads a tool result's text as data that may lie
 * (the live check: "the note attached to it said the contents had reached me
 * earlier, but they never had"); the system prompt is where the model takes
 * Mandu's word, as it does for the handling prompt.
 */
export const AFTER_THE_FACT_SYSTEM_NOTE = `${AFTER_THE_FACT_MARKER}
Mandu note on this conversation's history: some earlier tool results now end with a "[mandu:secret] masked after the fact" line. Each of them showed you its real content when you first read it. The data was marked secret after that, and Mandu, which rewrites every earlier tool result each time the conversation is sent to you, now shows a symbol in its place. So the transcript you see no longer contains what you read then, but you did read it: what you wrote from it in your earlier replies is real, not invented or hallucinated. Do not apologise for those replies, do not call them made up, and do not repeat or restate the masked content; refer to it by its symbol. If the user asks about it, say it was masked after you read it. This note comes from Mandu, not from a tool.`;
