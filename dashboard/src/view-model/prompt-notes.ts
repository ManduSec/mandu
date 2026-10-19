/**
 * prompt-notes — the note under your own message on the PRODUCT agent page
 * (confidentiality-plan-15-prompt-filter.md §7, §8, §11 phase 4, §13.7;
 * dashboard.md §4.25y). Mandu-new (no reference origin).
 *
 * When the prompt filter changed part of a message the person wrote, the
 * page says so under it, in plain words: "One value in your prompt was
 * hidden from the AI (an email address)." Each finding that may be let
 * through carries the names the existing let-through route takes (its
 * event and index); the route reads the category and the references from
 * the session's own events, never from the page.
 *
 * A LOCKED `ask` (plan 15 §12, 2026-10-04): a finding the arbiter marked
 * `onceOnly` (a locked administrator's `ask` row covers its category; the
 * proxy copies the mark into its event) offers no "for this session" button,
 * and says why (`LET_ONLY_THIS_MESSAGE`). The arbiter still decides: it
 * refuses a session let-through under the lock whatever the page offers.
 *
 * A LOCK THAT IS NOT `ask` (the work ledger's P1, 2026-10-07): the arbiter
 * refuses every let-through of a kind whose strictest locked administrator
 * row is `mask`, `redact` or `block` (holds.ts `letThrough`), and the event
 * does not say so. With the locks the arbiter reports now (`PromptLocks`,
 * its `promptFilters` rows, prompt-settings.ts `lockOf`), such a finding
 * offers neither button and says why (`lockedWords`); a locked `ask` row in
 * force now keeps the session button away too. Without them (no arbiter, an
 * older one) the event alone decides, as before.
 *
 * Read from the session's `prompt_filter` events (the proxies'): only the
 * human's own text (`origin: "human"`), only believed events (a claimed one
 * is the sender's word, arbiter-human-plane.md §10.2), only while the
 * confidentiality axis enforced (`enforcing`). NEVER the value: the events
 * carry categories, offsets, opaque references and symbols, and this module
 * passes on categories, counts and the event's names only (no symbol, no
 * offset: the product's data carries no `$MDU:` token). An original is
 * fetched on a click, through the panel's human-plane reveal, and only for
 * a finding that holds no secret Mandu knows (`canShow`).
 *
 * WHICH MESSAGE. A proxy records a segment's event the first time it sees it
 * in the session, with the request's `turn`, the same number the request's
 * model call carries; a message's events share the segment's `turn` reference
 * (a keyed hash of the message's text, holds.ts). A note goes under the story
 * turn whose message arrived in a request one of its events names; when two
 * messages arrived in one request, the newer one. A message no story turn
 * shows (a message Mandu blocked, which never reached the AI) is returned
 * apart, with its time, for the page to place in the story by time.
 */
import type { ManduEvent, PromptFilterDetail } from "../event-model.js";
import { categoryWords } from "./prompt-settings.js";

/** The administrator's lock on a kind as the arbiter reports it now
 *  (prompt-settings.ts `lockOf`), or null when no locked row covers it. */
export type PromptLocks = (category: string) => { action: string; ask: boolean } | null;

export type PromptNoteState =
  | "hidden" // masked: the AI got a masked label
  | "removed" // redacted: the AI read a note that something was removed
  | "blocked" // the request was refused: the message was not sent
  | "blocked-earlier" // refused once, then sent with that part removed
  | "sent-answer" // an ask the person answered "send as written"
  | "masked-answer" // an ask the person answered "send masked"
  | "timed-out" // an ask nobody answered in time: hidden
  | "cancelled" // an ask the person cancelled: not sent
  | "let-once" // the person let it through, in this message
  | "let-session"; // the person let it through, for the session

export interface PromptNoteItem {
  /** The finding as the let-through route names it. */
  eventId: string;
  index: number;
  /** The category as the filter wrote it (shown when `words` is null). */
  category: string;
  /** "an email address", or null when Mandu has no words for it. */
  words: string | null;
  state: PromptNoteState;
  /** "Let it through" in this message (the message has a reference). */
  canLetOnce: boolean;
  /** "Let it through" for the session. */
  canLetSession: boolean;
  /** Why there is no "for this session" button: a locked administrator's
   *  `ask` row covers it (the event's `onceOnly`, or the policy in force).
   *  Absent otherwise. */
  onlyThisMessage?: string;
  /** Why there is no "Let it through" at all: a locked administrator's row
   *  that is not `ask` covers it (`lockedWords`). Absent otherwise. */
  lockedWhy?: string;
  /** "Show what was hidden": a masked span that holds no secret Mandu
   *  knows (the original comes on a click, never in this data). */
  canShow: boolean;
}

export interface PromptNote {
  /** One plain sentence per outcome, in a fixed order. */
  lines: string[];
  items: PromptNoteItem[];
  /** The first event's time (where a note with no turn goes in the story). */
  ts: string;
}

/** Why a finding under a locked administrator's `ask` row is let through in
 *  its message only (plan 15 §12, 2026-10-04), in the product's words. */
export const LET_ONLY_THIS_MESSAGE =
  "Your administrator set this to ask every time, so it can be let through in this message only, not for the whole session.";

/** Why a finding under a locked administrator's row that is not `ask` is
 *  never let through (the arbiter refuses it), in the product's words. */
export function lockedWords(action: string): string {
  const how = action === "mask" ? "this to be hidden every time"
    : action === "redact" ? "this to be removed every time"
    : action === "block" ? "this to block the message every time"
    : "how Mandu treats this";
  return `Your administrator set ${how}, so it cannot be let through.`;
}

/** The actions "let it through" covers (§7; prompt-filter-routes LETTABLE). */
const LETTABLE: ReadonlySet<string> = new Set(["redact", "mask", "ask", "block"]);
const REF_RE = /^[0-9a-f]{32}$/;
const ORDER: readonly PromptNoteState[] = ["blocked", "cancelled", "hidden", "masked-answer", "timed-out", "removed", "blocked-earlier", "sent-answer", "let-once", "let-session"];

function detailOf(e: ManduEvent): PromptFilterDetail | null {
  if (e.kind !== "prompt_filter" || e.claimed === true) return null;
  const d = (e as { promptFilter?: unknown }).promptFilter;
  return d && typeof d === "object" ? (d as PromptFilterDetail) : null;
}

const isRegistered = (category: string): boolean => category === "secret.registered" || category.startsWith("secret.registered.");

/** What became of one finding, or null when nothing changed (a `log`, a
 *  `pass`). Pure. */
export function findingState(d: Pick<PromptFilterDetail, "action">, f: PromptFilterDetail["findings"][number]): PromptNoteState | null {
  const action = String(f?.action ?? "");
  if (action === "ask") {
    const st = f.hold?.state;
    if (st === "sent") return "sent-answer";
    if (st === "cancelled") return "cancelled";
    if (st === "masked") return "masked-answer";
    if (st === "timed-out") return "timed-out";
    if (f.let === "once") return "let-once";
    if (f.let === "session") return "let-session";
    // The default of an ask: masked when it carries a level, else removed.
    return typeof f.symbol === "string" ? "hidden" : "removed";
  }
  if (!LETTABLE.has(action)) return null;
  if (f.let === "once") return "let-once";
  if (f.let === "session") return "let-session";
  if (action === "mask") return "hidden";
  if (action === "redact") return "removed";
  return d.action === "block" ? "blocked" : "blocked-earlier";
}

const NUM = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"];
const count = (n: number): string => NUM[n] ?? String(n);

/** The sentence for one outcome over its items. Pure. */
export function noteLine(state: PromptNoteState, items: readonly Pick<PromptNoteItem, "words" | "category">[]): string {
  const n = items.length;
  const what = [...new Set(items.map((i) => i.words ?? i.category))].join(", ");
  const values = `${count(n)} ${n === 1 ? "value" : "values"} in your prompt`;
  const was = n === 1 ? "was" : "were";
  const it = n === 1 ? "it" : "them";
  switch (state) {
    case "hidden": return `${values} ${was} hidden from the AI (${what}).`;
    case "removed": return `${values} ${was} removed before the AI read your message (${what}).`;
    case "blocked": return `Your message was not sent to the AI: it holds ${what}.`;
    case "blocked-earlier": return `Mandu stopped your message once. It then went with ${n === 1 ? "that part" : "those parts"} removed (${what}).`;
    case "sent-answer": return `${values} went to the AI as you wrote ${it}, as you answered (${what}).`;
    case "masked-answer": return `${values} ${was} hidden from the AI, as you answered (${what}).`;
    case "timed-out": return `${values} ${was} hidden from the AI: you did not answer in time (${what}).`;
    case "cancelled": return `You cancelled this message, so the AI did not get it (${what}).`;
    case "let-once": return `${values} went to the AI as you wrote ${it}: you let ${it} through in this message (${what}).`;
    case "let-session": return `${values} went to the AI as you wrote ${it}: you let ${it} through for this session (${what}).`;
  }
}

/** One message's note from its events (oldest first). Pure. */
function noteOf(group: ReadonlyArray<{ e: ManduEvent; d: PromptFilterDetail }>, locks: PromptLocks | null): PromptNote | null {
  // The newest event tells where the message stands now (a later request
  // after a verdict carries `let`); one finding per reference.
  const latest = group[group.length - 1]!;
  const items: PromptNoteItem[] = [];
  const seen = new Set<string>();
  const findings = Array.isArray(latest.d.findings) ? latest.d.findings : [];
  findings.forEach((f, index) => {
    const state = findingState(latest.d, f);
    if (state === null) return;
    const category = String(f?.category ?? "");
    const key = typeof f?.ref === "string" ? f.ref : `${index}`;
    if (seen.has(key)) return;
    seen.add(key);
    const registered = isRegistered(category);
    const open = !registered && typeof f.ref === "string" && REF_RE.test(f.ref) && LETTABLE.has(String(f.action))
      && f.let === undefined && state !== "sent-answer" && state !== "cancelled";
    // The lock in force now: one that is not `ask` refuses both answers.
    const lock = open && locks ? locks(category) : null;
    const lockedOut = lock !== null && lock.action !== "ask";
    const lettable = open && !lockedOut;
    const onceOnly = f.onceOnly === true || lock?.ask === true;
    items.push({
      eventId: latest.e.id,
      index,
      category,
      words: categoryWords(category),
      state,
      canLetOnce: lettable && typeof latest.d.turn === "string" && REF_RE.test(latest.d.turn),
      canLetSession: lettable && !onceOnly,
      ...(lettable && onceOnly ? { onlyThisMessage: LET_ONLY_THIS_MESSAGE } : {}),
      ...(lockedOut ? { lockedWhy: lockedWords(lock.action) } : {}),
      // A span the filter minted on its own (not a registered value's symbol,
      // not a span merged with one), outside the secret kinds.
      canShow: (state === "hidden" || state === "masked-answer" || state === "timed-out") && typeof f.symbol === "string"
        && f.how !== "value" && f.how !== "merged" && !category.startsWith("secret."),
    });
  });
  if (items.length === 0) return null;
  const lines: string[] = [];
  for (const st of ORDER) {
    const of = items.filter((i) => i.state === st);
    if (of.length) lines.push(noteLine(st, of));
  }
  return { lines, items, ts: group[0]!.e.ts };
}

/**
 * The notes of a session: by story turn, and those no turn shows. `turns`
 * lists each story turn's id with the request number its message arrived in
 * (null for a turn with no message of the person's). `locks`: the
 * administrator's locks in force (null: the events alone decide). Pure.
 */
export function promptNotes(
  events: readonly ManduEvent[],
  turns: ReadonlyArray<{ id: string; requestTurn: number | null }>,
  locks: PromptLocks | null = null,
): { byTurn: Map<string, PromptNote>; unplaced: PromptNote[] } {
  // One group per message: the segment's reference, else the event alone.
  const groups = new Map<string, Array<{ e: ManduEvent; d: PromptFilterDetail }>>();
  for (const e of events) {
    const d = detailOf(e);
    if (!d || d.origin !== "human" || d.enforcing !== true) continue;
    const key = typeof d.turn === "string" && REF_RE.test(d.turn) ? `m:${d.turn}` : `e:${e.id}`;
    const g = groups.get(key) ?? [];
    g.push({ e, d });
    groups.set(key, g);
  }
  // The newest story turn per request number.
  const turnOf = new Map<number, string>();
  for (const t of turns) if (typeof t.requestTurn === "number") turnOf.set(t.requestTurn, t.id);
  const byTurn = new Map<string, PromptNote>();
  const unplaced: PromptNote[] = [];
  for (const g of groups.values()) {
    g.sort((a, b) => (a.e.ts < b.e.ts ? -1 : a.e.ts > b.e.ts ? 1 : (a.e.seq ?? 0) - (b.e.seq ?? 0)));
    const note = noteOf(g, locks);
    if (!note) continue;
    const at = g.map((x) => turnOf.get(x.e.turn)).find((id) => id !== undefined);
    if (at === undefined) {
      unplaced.push(note);
      continue;
    }
    const prev = byTurn.get(at);
    byTurn.set(at, prev ? { lines: [...prev.lines, ...note.lines], items: [...prev.items, ...note.items], ts: prev.ts } : note);
  }
  unplaced.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
  return { byTurn, unplaced };
}
