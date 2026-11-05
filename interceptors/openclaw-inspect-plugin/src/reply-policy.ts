/**
 * reply-policy — what the plugin's `message_sending` hook does with an
 * outgoing chat reply (docs/design/agents/openclaw-plugin.md §3.5). PURE.
 *
 * Mandu OpenClaw plugin (interceptors/openclaw-inspect-plugin). Mandu-new.
 *
 * A reply goes to a chat, not the local terminal, so it is egress: the reply
 * filter's deep desymbolize (which serves the human at their own terminal)
 * does not apply. The decision, in order:
 *   1. the tripwire found a registered secret VALUE in the reply, bound for
 *      a destination no binding admits → CANCEL the reply (the plugin cannot
 *      mask it back: the hits name the placeholder, never where the value
 *      sits, and no value may leave);
 *   2. a release put values back where a rule binds this destination →
 *      SEND the released text;
 *   3. otherwise → leave the reply UNCHANGED: placeholders stay placeholders.
 * A failed check or release is case 3 (the hook's own error path: OpenClaw
 * logs a throw from `message_sending` and sends the original, which carries
 * placeholders only). The tripwire is the backstop, not the guarantee: the
 * guarantee is that the model only ever saw placeholders (the proxy).
 */

import type { FingerprintScanResult, ReleaseAnswer } from "./hook-arbiter.js";

/** Mandu's placeholder (arbiter/symbol-table/symbol-format.ts, the default
 *  `$MDU` format, with its field path). */
export const PLACEHOLDER_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;

/** The distinct placeholders in `text`, in order of first appearance. */
export function placeholdersIn(text: string): string[] {
  const seen = new Set<string>();
  for (const m of text.matchAll(PLACEHOLDER_RE)) seen.add(m[0].replace(/\.+$/, ""));
  return [...seen];
}

export type ReplyVerdict =
  | { action: "unchanged"; placeholders: string[] }
  | { action: "release"; content: string; released: string[]; kept: string[] }
  | { action: "cancel"; reason: string; hits: Array<{ symbol: string; level: string }> };

export interface ReplyFacts {
  content: string;
  placeholders: string[];
  /** The tripwire's answer, or null when it could not run. */
  scan: FingerprintScanResult | null;
  /** The release's answer, or null when none ran or it failed. */
  release: ReleaseAnswer | null;
}

/** The text a cancelled reply's reason carries (OpenClaw records it). */
export const CANCEL_REASON =
  "Mandu cancelled this reply: it carries the value of a protected secret, and no rule allows that value to this chat.";

export function decideReply(f: ReplyFacts): ReplyVerdict {
  if (f.scan?.tripped === true && f.scan.hits.length > 0) {
    return { action: "cancel", reason: CANCEL_REASON, hits: f.scan.hits.map((h) => ({ symbol: h.symbol, level: h.level })) };
  }
  if (f.release !== null && f.release.released.length > 0 && f.release.text !== f.content) {
    const released = new Set(f.release.released);
    return {
      action: "release",
      content: f.release.text,
      released: [...released],
      kept: f.placeholders.filter((p) => !released.has(p)),
    };
  }
  return { action: "unchanged", placeholders: f.placeholders };
}
