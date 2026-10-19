/**
 * typing — a placeholder the agent types a key at a time
 * (docs/design/agents/devtools-relay.md §3.3). Mandu-new (no reference
 * origin).
 *
 * Agents that type like a person (browser-use's `input`, Puppeteer's
 * `type`) send one `Input.dispatchKeyEvent` per character, so no single
 * command carries a whole `$MDU:*` placeholder and release.ts never sees
 * one: the page got the placeholder's literal characters. KeyRun holds the
 * key events of a run that could still be a placeholder, from its `$` on:
 *
 *   - each held command is answered at once (the agent waits for each);
 *   - while the text typed so far could grow into a placeholder or a
 *     lookalike of one (heldPrefix: the placeholder's shape with any code
 *     of up to LOOKALIKE_MAX_CODE characters, symbols.ts), the next key is
 *     held too, and so is every key event that types nothing (a keyDown
 *     without text, a keyUp), up to MAX_RUN_TEXT characters and
 *     MAX_RUN_KEYS events;
 *   - a LOOKALIKE is decided on the key that closes its code (the `]`):
 *     from there it can only stay a lookalike, which names nothing, so the
 *     run says so at once (`decide`) and the relay refuses THAT key
 *     (release.ts refuses a lookalike without asking the arbiter). The
 *     agent's typing command then fails while it types, before it moves on
 *     to its next action (browser-use falls back to a script click when a
 *     click's mouse event carries an error, so a refusal told on the click
 *     submitted the form without the value: the 2026-10-19 expense-report
 *     demo). The run goes on holding the token's remaining keys, and it ends
 *     DROPPED: nothing of it reaches the page;
 *   - a PLACEHOLDER's code is checked on the same key (`check`, since
 *     2026-10-19): the relay asks the arbiter whether its base
 *     (`$MDU:kind[code]`) names a row, and when it does not (a hex code the
 *     model made up), or the arbiter cannot answer, refuses that key and the
 *     run (`refuse()`), which ends DROPPED as a lookalike's does. Known, the
 *     run goes on and is decided at its end, as before (whether the site may
 *     have it, and a field name, need the whole name);
 *   - the run ends at a key that cannot extend it, at any other command,
 *     or when the agent goes quiet (the relay's timer). Its text is then
 *     either exactly one placeholder or one lookalike, and is RELEASED
 *     through release.ts (the same origin check, decision and
 *     isolated-world insert as a whole `Input.insertText`; a lookalike is
 *     refused there, as it names nothing), with the textless key events
 *     that came after its last character forwarded after it (an Enter's
 *     keyDown lands after the value); or it is neither, and every held
 *     command is FORWARDED
 *     as the agent sent it, in order (the page gets what it would have).
 *
 * Nothing here decides a release: a held run is only ever released by
 * release.ts, dropped after release.ts refused it, or forwarded unchanged.
 * Pure; the relay (pair.ts) acts on its answers.
 */
import { LOOKALIKE_MAX_CODE, wholeLookalike, wholePlaceholder } from "./symbols.js";

export { wholePlaceholder };

/** One of the agent's commands, as the relay keeps it. */
export interface KeyCommand {
  id: number;
  method: string;
  params?: Record<string, unknown>;
  sessionId?: string;
}

const HEAD = "$MDU:";
const KIND_START = /[a-zA-Z_]/;
const KIND_REST = /[a-zA-Z0-9_]/;
const HEX = /[0-9a-f]/;
const NAME_REST = /[a-zA-Z0-9_[\].]/;
const CODE = /[^\s\]]/;

/** The most characters a run holds (a placeholder typed a key at a time
 *  that is longer is typed as written: the page gets the literal). */
export const MAX_RUN_TEXT = 512;
/** The most key events a run holds (three per character, browser-use's
 *  way, with room for textless ones). */
export const MAX_RUN_KEYS = 4 * MAX_RUN_TEXT;

/** Whether `s` is the start of some placeholder (`$MDU:kind[hash].NAME`,
 *  symbols.ts symbolPattern): a key more could still make one. Pure. */
export function placeholderPrefix(s: string): boolean {
  return shapePrefix(s, HEX, 8, 4);
}

/** Whether `s` is the start of a placeholder or of a lookalike of one
 *  (symbols.ts lookalikePattern: any code of 1 to LOOKALIKE_MAX_CODE
 *  characters that are not whitespace or `]`): what a run holds. Pure. */
export function heldPrefix(s: string): boolean {
  return s.length <= MAX_RUN_TEXT && shapePrefix(s, CODE, LOOKALIKE_MAX_CODE, 1);
}

/** The prefix grammar, with the code's characters and length as given. */
function shapePrefix(s: string, code: RegExp, max: number, min: number): boolean {
  if (s.length <= HEAD.length) return HEAD.startsWith(s);
  if (!s.startsWith(HEAD)) return false;
  let i = HEAD.length;
  if (!KIND_START.test(s[i]!)) return false;
  i++;
  while (i < s.length && KIND_REST.test(s[i]!)) i++;
  if (i === s.length) return true;
  if (s[i] !== "[") return false;
  i++;
  let n = 0;
  while (i < s.length && n < max && code.test(s[i]!)) { i++; n++; }
  if (i === s.length) return true;
  if (s[i] !== "]" || n < min) return false;
  i++;
  if (i === s.length) return true;
  if (s[i] !== ".") return false;
  i++;
  if (i === s.length) return true;
  if (!KIND_START.test(s[i]!)) return false;
  i++;
  while (i < s.length && NAME_REST.test(s[i]!)) i++;
  return i === s.length;
}

/** The characters a key event types, or null for one that types nothing
 *  (`Input.dispatchKeyEvent` types its `text` on `keyDown` and `char`). */
export function typedText(cmd: KeyCommand): string | null {
  if (cmd.method !== "Input.dispatchKeyEvent") return null;
  const p = cmd.params ?? {};
  if (p["type"] !== "keyDown" && p["type"] !== "char") return null;
  const t = p["text"];
  return typeof t === "string" && t !== "" ? t : null;
}

/** What a run came to. `dropped`: a run already refused on its way
 *  (`decide`): none of its keys go, the textless ones after its last
 *  character follow as for a release. */
export type RunEnd =
  | { kind: "release"; text: string; sessionId?: string; after: KeyCommand[] }
  | { kind: "dropped"; after: KeyCommand[] }
  | { kind: "forward"; commands: KeyCommand[] };

/** What to do with a key event. */
export type KeyStep =
  | { kind: "forward" }
  | { kind: "hold" }
  /** held, and the run's text just became a whole lookalike (its code
   *  closed): refuse it now, on this key; the run ends `dropped` */
  | { kind: "decide"; text: string; sessionId?: string }
  /** held, and the run's text just became a placeholder's BASE (its hex
   *  code closed): the relay asks the arbiter whether the base names a row,
   *  and on no (or no answer) refuses this key and calls `refuse()`, so the
   *  run ends `dropped`; on yes the key is held like any other */
  | { kind: "check"; base: string; sessionId?: string }
  /** the run ended before this key: act on `end`, then take the key again */
  | { kind: "ended"; end: RunEnd };

/** The run of held key events (one per relay pair). */
export class KeyRun {
  private held: Array<{ cmd: KeyCommand; text: string | null }> = [];
  private typed = "";
  private sessionId: string | undefined;
  /** the run was refused on its way (`decide`, or a `check` the relay
   *  refused): it ends dropped */
  private refused = false;

  get holding(): boolean {
    return this.held.length > 0;
  }

  /** The relay refused the held run on its way (a `check` answered
   *  unknown, or not at all): it ends dropped, whatever it grows into. */
  refuse(): void {
    if (this.holding) this.refused = true;
  }

  /** One `Input.dispatchKeyEvent` whose own text carries no whole
   *  placeholder or lookalike (release.ts takes those). */
  key(cmd: KeyCommand): KeyStep {
    const text = typedText(cmd);
    if (!this.holding) {
      if (text !== "$") return { kind: "forward" };
      this.held = [{ cmd, text }];
      this.typed = text;
      this.sessionId = cmd.sessionId;
      return { kind: "hold" };
    }
    if (cmd.sessionId !== this.sessionId) return { kind: "ended", end: this.end()! };
    if (this.held.length >= MAX_RUN_KEYS) return { kind: "ended", end: this.end()! };
    if (text === null) {
      this.held.push({ cmd, text });
      return { kind: "hold" };
    }
    if (text.length === 1 && heldPrefix(this.typed + text)) {
      this.held.push({ cmd, text });
      this.typed += text;
      // The code just closed and is no placeholder's: the run can only end
      // as this lookalike (or a longer one), so it is decided now.
      if (!this.refused && text === "]" && wholeLookalike(this.typed)) {
        this.refused = true;
        return { kind: "decide", text: this.typed, ...(this.sessionId !== undefined ? { sessionId: this.sessionId } : {}) };
      }
      // The code just closed and is a placeholder's: whether the table knows
      // its base is known now, so the relay asks (`check`). Only at the
      // first `]` (a field may carry its own, `.a[0]`).
      if (!this.refused && text === "]" && this.typed.indexOf("]") === this.typed.length - 1 && wholePlaceholder(this.typed)) {
        return { kind: "check", base: this.typed, ...(this.sessionId !== undefined ? { sessionId: this.sessionId } : {}) };
      }
      return { kind: "hold" };
    }
    return { kind: "ended", end: this.end()! };
  }

  /** End the run (another command, or the agent went quiet); null when
   *  nothing is held. */
  end(): RunEnd | null {
    if (!this.holding) return null;
    const held = this.held;
    const typed = this.typed;
    const sessionId = this.sessionId;
    const refused = this.refused;
    this.held = [];
    this.typed = "";
    this.sessionId = undefined;
    this.refused = false;
    let last = -1;
    held.forEach((h, i) => { if (h.text !== null) last = i; });
    // Refused on its way: whatever it grew into ("…].", say), none of it goes.
    if (refused) return { kind: "dropped", after: held.slice(last + 1).map((h) => h.cmd) };
    // A lookalike goes to release.ts too, which refuses it: forwarded, its
    // characters would reach the page and the model would not learn.
    if (!wholePlaceholder(typed) && !wholeLookalike(typed)) return { kind: "forward", commands: held.map((h) => h.cmd) };
    return {
      kind: "release", text: typed, ...(sessionId !== undefined ? { sessionId } : {}),
      after: held.slice(last + 1).map((h) => h.cmd),
    };
  }
}
