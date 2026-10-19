/**
 * view-model/gate-rewrite — a call the model proxy rewrote so that it could
 * not run (dashboard.md §4.25b, *A call Mandu rewrote reads as what it
 * stopped*).
 *
 * Mandu-new (no reference origin). WHY: the proxies enforce an exec or net
 * block by rewriting the call before the agent gets it, and their sniffers
 * record the call as rewritten:
 *   - the exec gate turns a command into `echo '<notice>' 1>&2; exit 77`
 *     (exec-gate.ts `blockSentinelCommand`, byte-identical in both proxies;
 *     an argv field becomes `["/bin/sh", "-c", <that>]`);
 *   - the net gate turns a fetch's URL into one on the reserved host
 *     `blocked.mandu.invalid` (net-gate.ts `DENIED_HOST`), and a search's
 *     query into its notice (`netBlockNotice`).
 * The session page worded that input as the AI's own call ("Ran echo
 * 'mandu-exec-gate: blocked …'", "Opened a web page on
 * `blocked.mandu.invalid`"). This module recognizes the three rewrites,
 * exactly as the proxies write them; agent-page.ts words such a step as the
 * block it was, and only when a check of the same kind blocked the call: a
 * model can write the sentinel itself, so the shape alone claims nothing.
 *
 * A command is the exec sentinel only when it is NOTHING ELSE: the whole
 * command, its notice single-quoted (the proxies strip every single quote
 * from it), so no other program can hide in a step the page calls stopped.
 *
 * `noticeWhy` words the reason the exec notice gives (the proxies'
 * `plainBlockWords`) where the product can say it: a session that read a
 * secret, a no you gave earlier, the service not answering, a wait for your
 * OK. The integrity axis's reason (a placeholder run as code) and the
 * catch-all ("Mandu rules do not allow it") give no line. The words are the
 * product's (rule-words.ts `TERMS`): never symbol, egress or binding. Pure.
 */

import type { StoryPart } from "./agent-page-types.js";

/** What the proxy rewrote: a command (with the plain reason its notice
 *  gives), a web fetch, or a web search. */
export type GateRewrite =
  | { kind: "command"; reason: string }
  | { kind: "fetch" }
  | { kind: "search" };

/** The exec gate's sentinel, whole (exec-gate.ts `blockSentinelCommand`
 *  over `blockNoticeText`): the plain reason, then the arbiter's. */
const EXEC_SENTINEL_RE = /^echo 'mandu-exec-gate: blocked, nothing ran: ([^']*?)\. detail: [^']*' 1>&2; exit 77$/;

/** The reserved host a blocked fetch's URL is rewritten to (net-gate.ts). */
export const DENIED_HOST = "blocked.mandu.invalid";
/** The reserved host a fetch the gate stopped AND asked the user about is
 *  rewritten to (net-gate.ts `ASKED_HOST`, confidentiality.md §4). */
export const ASKED_HOST = "asked.mandu.invalid";

/** The net gate's notice, put in place of a search's query. */
const NET_NOTICE_PREFIX = "mandu-net-gate: network use blocked, nothing was sent: ";

/** The plain reason of an exec sentinel command, or null. */
function sentinelReason(v: unknown): string | null {
  const cmd = typeof v === "string" ? v
    : Array.isArray(v) && v.length === 3 && v[0] === "/bin/sh" && v[1] === "-c" && typeof v[2] === "string" ? v[2]
    : null;
  const m = cmd === null ? null : EXEC_SENTINEL_RE.exec(cmd);
  return m ? m[1]! : null;
}

function deniedUrl(v: unknown): boolean {
  if (typeof v !== "string") return false;
  try {
    const host = new URL(v).hostname;
    return host === DENIED_HOST || host === ASKED_HOST;
  } catch {
    return false;
  }
}

/** The rewrite a call's recorded input (its JSON) shows, or null: a field
 *  that is the exec sentinel, then a URL on the reserved host, then a
 *  `query` that is the net gate's notice. Top-level fields only, as the
 *  proxies rewrite them. */
export function gateRewrite(input: string | null | undefined): GateRewrite | null {
  if (!input) return null;
  let args: unknown;
  try {
    args = JSON.parse(input);
  } catch {
    return null;
  }
  if (!args || typeof args !== "object" || Array.isArray(args)) return null;
  const fields = Object.values(args as Record<string, unknown>);
  for (const v of fields) {
    const reason = sentinelReason(v);
    if (reason !== null) return { kind: "command", reason };
  }
  if (fields.some(deniedUrl)) return { kind: "fetch" };
  const query = (args as Record<string, unknown>)["query"];
  if (typeof query === "string" && query.startsWith(NET_NOTICE_PREFIX)) return { kind: "search" };
  return null;
}

/** The check kind that makes each rewrite: only a block by it backs the
 *  page's words. */
export function rewriteCheckKind(r: GateRewrite): "exec_action" | "net_action" {
  return r.kind === "command" ? "exec_action" : "net_action";
}

const t = (text: string): StoryPart => ({ kind: "text", text });

/** The exec notice's reason in the product's words, or null where the page
 *  does not word it. Keyed on the start of the proxies' `plainBlockWords`. */
export function noticeWhy(reason: string): StoryPart[] | null {
  // A HIGH session's command (confidentiality.md §4, "The human half"):
  // stopped and asked, or blocked by your answer. Before the generic line.
  if (reason.startsWith("this session has read a secret, and Mandu cannot prove this command stays off the network, so Mandu stopped it and asked")) {
    return [t("This session read a secret, and Mandu cannot be sure this command stays off the network, so it asked for your OK.")];
  }
  if (reason.startsWith("this session has read a secret, and the user blocked this command")) {
    return [t("This session read a secret, and you blocked this command for it.")];
  }
  if (reason.startsWith("this session has read a secret, and Mandu cannot prove this command stays off the network")) {
    return [t("This session read a secret, and Mandu cannot be sure this command stays off the network. Start a new session for work that needs it.")];
  }
  if (reason.startsWith("you said no to running this earlier")) return [t("You said no to running it earlier.")];
  if (reason.startsWith("the Mandu service is not answering")) return [t("Mandu's service did not answer, so Mandu blocked it to be safe.")];
  if (reason.startsWith("running it needs your OK")) return [t("Running it needs your OK.")];
  return null;
}
