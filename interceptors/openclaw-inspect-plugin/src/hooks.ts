/**
 * hooks — the plugin's two OpenClaw hooks for a resident Gateway attached to
 * `mandu serve` (docs/design/agents/openclaw-plugin.md §3.5, §3.6).
 *
 * Mandu OpenClaw plugin (interceptors/openclaw-inspect-plugin). Mandu-new.
 *
 *   before_tool_call  the tamper policy (tamper-policy.ts): refuse a tool call
 *                     that names Mandu's state, the OpenClaw config, or
 *                     stopping the service. Pure and synchronous: it needs no
 *                     arbiter, so an unreachable arbiter changes nothing here.
 *                     OpenClaw fails this hook CLOSED (a throw blocks the call).
 *   message_sending   the reply decision (reply-policy.ts): placeholders stay
 *                     unless a rule binds the chat; a reply carrying a secret
 *                     VALUE is cancelled. OpenClaw fails this hook OPEN (a
 *                     throw is logged and the original is sent), which is safe
 *                     here: the original carries placeholders, never values,
 *                     unless the model was given a value, and the tripwire is
 *                     the backstop for that, not the guarantee.
 *
 * Only these two. The plugin does NOT register the tool-result middleware or
 * any hook that needs `hooks.allowConversationAccess` (before_model_resolve,
 * before_prompt_build, llm_*, agent_end, …): symbolization stays at the
 * model proxy (§3.1), and the installer grants no conversation access.
 * `reply_payload_sending` is not used either: with no release op there is
 * nothing to rewrite in a payload, and `message_sending` sees the same text
 * on its way to every channel.
 *
 * SESSIONS (attachment-session.ts): a hook's session is `openclaw:<agentId>`
 * of the agent the context names (before_tool_call's `agentId`; for a reply,
 * the agent in the Gateway's sessionKey), else the configured agent. The
 * Gateway's sessionKey rides each event (plugin-events.ts).
 */

import { agentIdOfSessionKey, attachmentSession, normalizeAgentId } from "./attachment-session.js";
import type { HookArbiter, ReplyDestination, ReplyReleaser } from "./hook-arbiter.js";
import type {
  BeforeToolCallEvent,
  BeforeToolCallResult,
  MessageHookContext,
  MessageSendingEvent,
  MessageSendingResult,
  OpenClawPluginApiLike,
  PluginLogger,
  ToolHookContext,
} from "./openclaw-api.js";
import { replyEvent, tamperEvent } from "./plugin-events.js";
import { decideReply, placeholdersIn } from "./reply-policy.js";
import type { FingerprintScanResult, ReleaseAnswer } from "./hook-arbiter.js";
import type { TamperPolicy } from "./tamper-policy.js";

/** The hooks the attachment registers, by name (manifest.test.ts pins it). */
export const ATTACHMENT_HOOKS = ["before_tool_call", "message_sending"] as const;

/** How long the reply hook waits on the arbiter before sending the reply
 *  unchanged (OpenClaw's own budget for the hook is 15 s). */
export const REPLY_ARBITER_TIMEOUT_MS = 3000;

export interface HookDeps {
  policy: TamperPolicy;
  /** The configured agent (the session when a context names none). */
  agentId: string;
  /** Lazy arbiter (the data socket); a rejection = unreachable. */
  getArbiter: () => Promise<HookArbiter>;
  releaser: ReplyReleaser;
  logger: PluginLogger;
  /** Test seam (default REPLY_ARBITER_TIMEOUT_MS). */
  arbiterTimeoutMs?: number;
}

/** Fire-and-forget emit: never awaited by a decision, never throws. */
function emitQuietly(deps: HookDeps, event: unknown): void {
  deps.getArbiter()
    .then((a) => a.emit(event))
    .catch(() => { /* observability only */ });
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`no answer within ${ms} ms`)), ms);
    t.unref?.();
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

/** The `before_tool_call` handler. */
export function createBeforeToolCall(deps: HookDeps): (event: BeforeToolCallEvent, ctx: ToolHookContext) => BeforeToolCallResult | undefined {
  return (event, ctx) => {
    const toolName = typeof event?.toolName === "string" ? event.toolName : (ctx?.toolName ?? "tool");
    const verdict = deps.policy.decide(toolName, event?.params ?? {}, event?.derivedPaths);
    if (!verdict.block) return undefined;
    const agentId = normalizeAgentId(ctx?.agentId ?? agentIdOfSessionKey(ctx?.sessionKey) ?? deps.agentId);
    deps.logger.warn(`[mandu] refused ${toolName}: names ${verdict.what} (${verdict.rule})`);
    emitQuietly(deps, tamperEvent({
      sessionId: attachmentSession(agentId),
      sessionKey: ctx?.sessionKey ?? null,
      agentId,
      toolName,
      toolCallId: event?.toolCallId ?? ctx?.toolCallId ?? null,
      rule: verdict.rule,
      what: verdict.what,
    }));
    return { block: true, blockReason: verdict.reason };
  };
}

/** The `message_sending` handler. */
export function createMessageSending(deps: HookDeps): (event: MessageSendingEvent, ctx: MessageHookContext) => Promise<MessageSendingResult | undefined> {
  return async (event, ctx) => {
    const content = typeof event?.content === "string" ? event.content : "";
    if (content === "") return undefined;
    const placeholders = placeholdersIn(content);
    const agentId = agentIdOfSessionKey(ctx?.sessionKey) ?? normalizeAgentId(deps.agentId);
    const sessionKey = typeof ctx?.sessionKey === "string" ? ctx.sessionKey : null;
    const destination: ReplyDestination = {
      channel: String(ctx?.channelId ?? ""),
      ...(ctx?.accountId ? { accountId: String(ctx.accountId) } : {}),
      ...(ctx?.conversationId ? { conversationId: String(ctx.conversationId) } : {}),
      to: String(event?.to ?? ""),
      ...(event?.threadId !== undefined ? { threadId: String(event.threadId) } : {}),
    };
    const timeout = deps.arbiterTimeoutMs ?? REPLY_ARBITER_TIMEOUT_MS;

    // 1. The tripwire, on every reply (a value the model was given could be
    // in a reply with no placeholder at all). The destination is "": a chat
    // is no host, so no host binding admits it and every hit counts.
    let scan: FingerprintScanResult | null = null;
    try {
      const arbiter = await withTimeout(deps.getArbiter(), timeout);
      // `reply`: a whole-masked tool result counts only by its secrets, not
      // by an ordinary line of it the model never saw (openclaw-plugin.md §3.5)
      scan = await withTimeout(arbiter.egressFingerprintScan([{ where: "body", text: content }], "", "reply"), timeout);
    } catch (err) {
      deps.logger.warn(`[mandu] reply not checked for protected values (${msgOf(err)}); sending it unchanged`);
    }

    // 2. The release, where a rule binds this chat (none can today:
    // hook-arbiter.ts NO_RELEASE). A failure keeps every placeholder.
    let release: ReleaseAnswer | null = null;
    if (placeholders.length > 0 && deps.releaser.live && !(scan?.tripped === true)) {
      try {
        release = await withTimeout(deps.releaser.release({ sessionKey: sessionKey ?? attachmentSession(agentId), destination, text: content, placeholders }), timeout);
      } catch (err) {
        deps.logger.warn(`[mandu] reply release failed (${msgOf(err)}); placeholders kept`);
      }
    }

    const verdict = decideReply({ content, placeholders, scan, release });
    const base = { sessionId: attachmentSession(agentId), sessionKey, agentId, destination: { channel: destination.channel, to: destination.to, ...(destination.accountId ? { accountId: destination.accountId } : {}), ...(destination.conversationId ? { conversationId: destination.conversationId } : {}) }, placeholders, checked: scan !== null };
    if (verdict.action === "cancel") {
      deps.logger.warn(`[mandu] cancelled a reply to ${destination.channel}: it carried ${verdict.hits.map((h) => h.symbol).join(", ")}`);
      emitQuietly(deps, replyEvent({ ...base, outcome: "cancelled", hits: verdict.hits }));
      return { cancel: true, cancelReason: verdict.reason };
    }
    if (verdict.action === "release") {
      emitQuietly(deps, replyEvent({ ...base, outcome: "released", released: verdict.released }));
      return { content: verdict.content };
    }
    if (placeholders.length > 0) emitQuietly(deps, replyEvent({ ...base, outcome: "kept" }));
    return undefined;
  };
}

/** Register the attachment hooks. Throws (failing the plugin load loudly)
 *  when the host has no typed hook API: an attachment without its hooks
 *  must say so at load, never run without them. */
export function registerAttachmentHooks(api: OpenClawPluginApiLike, deps: HookDeps): void {
  if (typeof api.on !== "function") {
    throw new Error("mandu-inspect: this OpenClaw has no plugin hook API (api.on); the attachment needs before_tool_call and message_sending");
  }
  api.on("before_tool_call", createBeforeToolCall(deps));
  api.on("message_sending", createMessageSending(deps), { timeoutMs: 15_000 });
}

function msgOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
