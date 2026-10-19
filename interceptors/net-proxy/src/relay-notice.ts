/**
 * relay-notice — the DevTools relay's refusals, told to the browser agent's
 * model on its next call (docs/design/agents/devtools-relay.md §3.4).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * WHY. The relay answers a refused placeholder with a DevTools error, and
 * some agents never show it to their model: browser-use swallows a
 * command's error, and its key-by-key typing defers the refusal to the next
 * input command, whose error it swallows too. Live (2026-10-19, the
 * expense-report demo) Gemini 2.5 Flash typed a made-up placeholder into the
 * card field, saw an empty field, typed the same one again, and submitted
 * without the card. Whatever the agent does with errors, its model's next
 * request goes through this proxy (model-note.ts), so the refusal goes in
 * there: agent-agnostic.
 *
 * THE RULE. The relay reports each refusal to the arbiter (`relayNotice`,
 * structured names only: arbiter/ipc/relay-notices.ts). On a Chat
 * Completions call that gets the handling note, the proxy also takes the
 * session's pending refusals (`takeRelayNotices`, which clears them: each is
 * told once) and appends them as ONE message at the END of `messages`,
 * after the latest message, so the model reacts to it in this turn:
 *
 *   { "role": "user", "content": "Mandu (the protection layer on this
 *     computer; this message is from Mandu, not from the user): your last
 *     attempt to type into a field on ledgerly.localhost typed nothing: …" }
 *
 * `user`, not `system`: a Chat Completions service hands a model whose own
 * API has one system prompt (Gemini, Claude) every `system` message as that
 * prompt, wherever it stood, so a late `system` message loses its place; a
 * `user` message stays where it is on every provider. The text says who
 * speaks, so the model does not take it for the person's request. The note
 * (the first `system` message) is not touched, so the prompt cache keeps it.
 *
 * A SITE THAT MAY NOT HAVE IT. An unbound site, or one that needs the
 * user's approval, is told as a site that may not have the secret: leave it
 * out and go on (`LEAVE_IT_OUT`), and ask the user only if they asked for
 * that secret to go there. The person stays in control: the open ask is
 * still on Mandu's Approvals page, and nothing is typed without its answer.
 *
 * WHY IT IS SAFE. The sentence is built here from the notice's fields, each
 * checked again (a kind and a cause from fixed lists, a host, `$MDU:` names):
 * no free text and no value can reach it, and a field that fails the check
 * is dropped. The names are ones the model typed or the relay showed it.
 * Utility only: an arbiter that cannot answer means no notice, never a
 * refused request.
 */

/** One refusal (arbiter/ipc/relay-notices.ts `RelayNoticeWire`, mirrored
 *  so this package typechecks standalone). */
export interface RelayNotice {
  /** `malformed`: a placeholder lookalike, never quoted (`symbols` is
   *  empty: its code is free text). */
  kind: "unknown" | "malformed" | "not-allowed" | "needs-approval" | "declined" | "failed";
  page?: string;
  symbols: string[];
  shown?: string[];
  cause?: "no-field" | "page-moved" | "frame" | "no-page" | "page-refused" | "unavailable";
}

/** Who speaks, first in the message. */
export const NOTICE_SPEAKER = "Mandu (the protection layer on this computer; this message is from Mandu, not from the user)";

/** The role the message goes in as (see the header). */
export const NOTICE_ROLE = "user";

const NAME_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z_][A-Za-z0-9_[\].]{0,255})?$/;
const HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])$/;

/** What a model does when a site may not have the secret (`not-allowed`, and
 *  `needs-approval` unless the user asked for that secret there): the task
 *  goes on without it, as a held request's *Send without it* does
 *  (egress-hold.md). Live (2026-10-19, the expense-report demo): told only
 *  to ask the user, Gemini 2.5 Flash stopped before posting a team-chat
 *  summary that never needed the card. */
export const LEAVE_IT_OUT = "leave it out, write the rest without it (name the secret in plain words if the text needs it, " +
  'such as "the card" or "the API key", never its placeholder), and go on with the task.';

const FAILED: Record<NonNullable<RelayNotice["cause"]>, string> = {
  "no-field": "no editable field had the focus. Click the field first, then type the placeholder again.",
  "page-moved": "the page moved to another site before the value was typed. Check which page is open, then type it again.",
  frame: "the focus was in a frame of another page. Click the field itself, then type it again.",
  "no-page": "the page has no web address a secret can be given to. Open the site's own page first.",
  "page-refused": "the page did not take the text. Try once more; if it fails again, tell the user.",
  unavailable: "Mandu could not check the placeholder just then. Try once more; if it fails again, tell the user.",
};

function names(list: readonly string[] | undefined): string[] {
  return Array.isArray(list) ? list.filter((s) => typeof s === "string" && NAME_RE.test(s)) : [];
}

function either(list: string[]): string {
  return list.length === 1 ? list[0]! : `${list.slice(0, -1).join(", ")} and ${list.at(-1)}`;
}

/** Why one refusal typed nothing, and what to do, or null for a notice
 *  that fails the check. Pure. */
export function noticeReason(n: RelayNotice): string | null {
  if (n.kind === "malformed") {
    const shown = names(n.shown);
    return "the text typed looks like a placeholder but is not one Mandu made. " +
      "Copy the placeholder character for character from the page that shows the secret, never make one up" +
      (shown.length > 0 ? ` (the pages showed ${shown.join(", ")}).` : ".");
  }
  const symbols = names(n.symbols);
  if (symbols.length === 0) return null;
  const sym = either(symbols);
  const site = typeof n.page === "string" && HOST_RE.test(n.page) ? n.page : null;
  switch (n.kind) {
    case "unknown": {
      const shown = names(n.shown);
      const is = symbols.length === 1 ? "is not a placeholder" : "are not placeholders";
      return `${sym} ${is} Mandu knows. Copy the placeholder character for character from the page that shows the secret` +
        (shown.length > 0 ? ` (the pages showed ${shown.join(", ")}).` : ".");
    }
    case "not-allowed": {
      const at = site ?? "this site";
      return `${at} may not have the secret ${sym}. Do not type it there again: ${LEAVE_IT_OUT} ` +
        `Only if the user asked for that secret to go to ${at}, tell them Mandu does not let that site have it.`;
    }
    case "needs-approval": {
      const at = site ?? "this site";
      return `${at} may not have the secret ${sym} without the user's approval in Mandu. ` +
        `Unless the user asked for that secret to go to ${at}, do not ask them: ${LEAVE_IT_OUT} ` +
        "If they did ask for it there, ask them to approve it in Mandu, then type it again.";
    }
    case "declined":
      return `the user chose to go on without ${sym}. Do not type it again; finish the task without it.`;
    case "failed":
      return n.cause !== undefined && Object.hasOwn(FAILED, n.cause) ? FAILED[n.cause] : null;
    default:
      return null;
  }
}

function where(n: RelayNotice): string {
  return typeof n.page === "string" && HOST_RE.test(n.page) ? `into a field on ${n.page}` : "into a field";
}

/** The notices that pass the check, each with its reason. Pure. */
export function toldNotices(notices: readonly RelayNotice[]): Array<{ n: RelayNotice; why: string }> {
  return notices.flatMap((n) => {
    if (typeof n !== "object" || n === null) return [];
    const why = noticeReason(n);
    return why === null ? [] : [{ n, why }];
  });
}

/** The message's text for these refusals, or null when none passes the
 *  check. Pure. */
export function relayNoticeText(notices: readonly RelayNotice[]): string | null {
  const told = toldNotices(notices);
  if (told.length === 0) return null;
  if (told.length === 1) return `${NOTICE_SPEAKER}: your last attempt to type ${where(told[0]!.n)} typed nothing: ${told[0]!.why}`;
  return `${NOTICE_SPEAKER}: your last ${told.length} attempts to type a placeholder typed nothing:\n` +
    told.map(({ n, why }) => `- ${where(n)}: ${why}`).join("\n");
}

/** `messages` with the notice message after the latest one (a new array). */
export function appendRelayNotice(messages: readonly unknown[], text: string): unknown[] {
  return [...messages, { role: NOTICE_ROLE, content: text }];
}
