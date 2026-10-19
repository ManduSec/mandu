/**
 * declassify-symbol — the ONE relay for `declassify_symbol` (§3.3 rung 3, the
 * in-context read), shared by every mount of the Mandu quarantine channel.
 *
 * Mandu-new module (2026-09-29, supported-agents.md §5.5 item 3). The logic moved
 * here, unchanged, from mcp-server.ts `handleDeclassify` so the MCP server
 * (Claude Code, OpenCode, Codex) and the OpenClaw plugin tool
 * (interceptors/openclaw-inspect-plugin) run the same bytes. Only the mount
 * differs: the MCP server wraps the outcome in a JSON-RPC tool result, the
 * plugin in an OpenClaw tool result.
 *
 * The ARBITER decides (arbiter/policy/declassify.ts decideDeclassify and the
 * server's `declassifySymbol` op: refusals, the human approval queue, the
 * watermark raised before the content is handed over). This module only
 * relays, and it has NO fallback: when the arbiter refuses, lacks the op, or
 * cannot be reached, the outcome is an error with no content. A "try
 * resolve() instead" path would hand raw content to T-LLM with no gate and
 * no watermark, which is the leak rung 3 exists to close.
 */

import type { Arbiter } from "./arbiter-client.js";
import { INSPECT_FALLBACK_SESSION } from "./inspect-symbol.js";

/** What the relay needs: the arbiter's rung-3 op and the Mandu session the
 *  watermark lands on (the model proxy's session for this run). */
export interface DeclassifyDeps {
  arbiter: Pick<Arbiter, "declassify">;
  sessionId?: string;
}

export type DeclassifyOutcome =
  | { ok: true; text: string }
  | { ok: false; error: string };

/**
 * The line that precedes a released value. The arbiter trusts a declassify
 * tool result only when it is the released value alone or this one line, a
 * blank line and the value (arbiter/ipc/server.ts declassifyResultTrusted:
 * `^\[DECLASSIFIED[^\n\]]*\]$`), so the notice must stay one line with no `]`
 * before its end.
 *
 * The words say what the session gate does (it stops the call and asks the
 * user on the Approvals page; confidentiality.md §4, "The human half",
 * 2026-10-11) and tell the model to keep making calls and to make a stopped
 * one again after the user answers: "requires the user's approval" read as
 * "do not try", and the model asked the user to approve a shell command
 * that was never issued (handling-prompt.md §7, §8).
 */
export function declassifiedNotice(watermark: string | undefined): string {
  return (
    `[DECLASSIFIED — this session is now HIGH (${watermark ?? "secret"}). ` +
    `Requests to the hosts this content is bound to still go through; any other network request or shell command that could carry it out is stopped while Mandu asks the user on its Approvals page. ` +
    `Keep making the calls the user asks for and let Mandu decide each one: never refuse one yourself or ask the user to approve it first; if Mandu stops one, tell the user and make it again after they answer. ` +
    `Do not repeat this content into any tool call you would not want released.]`
  );
}

/** Relay one `declassify_symbol` call to the arbiter. Never throws. */
export async function declassifySymbol(
  deps: DeclassifyDeps,
  rawArgs: unknown,
): Promise<DeclassifyOutcome> {
  const args = isRecord(rawArgs) ? rawArgs : {};
  const symbol = typeof args.symbol === "string" ? args.symbol : "";
  const reason = typeof args.reason === "string" ? args.reason : "";
  if (!symbol) {
    return { ok: false, error: "declassify_symbol: 'symbol' is required" };
  }
  // No Mandu scope → no release. The arbiter raises the watermark on the
  // session this call names, and the model proxy gates the launcher's scope;
  // a release under another session (none, empty, or the stdio server's
  // inspect fallback) would leave the gated session looking clean while the
  // model holds the secret. Refused before the arbiter is asked, so nothing
  // is queued or released.
  const session = deps.sessionId?.trim();
  if (!session || session === INSPECT_FALLBACK_SESSION) {
    return {
      ok: false,
      error:
        "declassify_symbol: refusing (fail closed): no Mandu scope is configured (MANDU_SCOPE_ID), " +
        "so the release could not be watermarked on the session the proxy gates. This is by design — do not retry.",
    };
  }
  if (!deps.arbiter.declassify) {
    return { ok: false, error: "declassify_symbol: unavailable on this arbiter — use inspect_symbol" };
  }

  let verdict;
  try {
    verdict = await deps.arbiter.declassify({ symbol, sessionKey: session, reason });
  } catch (err) {
    // Fail closed: an arbiter that cannot answer does not get to be read as a yes.
    return { ok: false, error: `declassify_symbol: arbiter error: ${msgOf(err)}` };
  }

  if (!verdict.allowed || verdict.value === null) {
    const suffix = verdict.requiresApproval
      ? " The user has been asked to approve this; stop and tell them you are waiting."
      : " This is by design — do not retry.";
    return { ok: false, error: `declassify_symbol: ${verdict.reason}${suffix}` };
  }

  // ALLOWED. The arbiter has already raised the session watermark: it does so
  // BEFORE handing over the content, so there is no window in which the model
  // holds the secret while the session still looks clean.
  return { ok: true, text: `${declassifiedNotice(verdict.watermark)}\n\n${verdict.value}` };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function msgOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
