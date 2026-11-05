/**
 * plugin-events — the observability events the plugin's hooks emit.
 *
 * Mandu OpenClaw plugin (interceptors/openclaw-inspect-plugin). Mandu-new.
 * The subset of the canonical schema (dashboard/src/event-model.ts) these
 * events use, declared locally so the package typechecks standalone, as
 * inspect-mcp/src/event-model.ts does. The arbiter stores them as CLAIMS
 * (they arrive on the data socket, openclaw-plugin.md §3.3).
 *
 * NO CONTENT: a reply event carries counts and placeholder names, a tamper
 * event the tool name and the rule. Never the reply text, never a tool
 * call's arguments (a refused call's arguments name Mandu's paths; a
 * cancelled reply holds a secret value).
 *
 * `openclaw` carries the Gateway's identity of the act: its sessionKey (the
 * conversation), the agent, and for a reply the destination, so the session
 * page can tell conversations apart inside one `openclaw:<agentId>` session.
 */

import { randomBytes } from "node:crypto";

export type PluginEventKind = "tool_use" | "egress_decision";

export interface PluginEvent {
  id: string;
  sessionId: string;
  turn: number;
  ts: string;
  seq: number;
  callId: string | null;
  parentId: string | null;
  kind: PluginEventKind;
  view: "AgentView" | "HumanView";
  boundary: "shell" | "network";
  emitter: "openclaw-plugin";
  input: null;
  output: null;
  policy: {
    usage: "allow" | "deny";
    reason: string;
    ruleRef: { source: "rule" | "fail-closed"; id: string };
  };
  invariant: { violatedInvariant: false };
  openclaw: {
    sessionKey: string | null;
    agentId: string;
    toolName?: string;
    destination?: { channel: string; accountId?: string; conversationId?: string; to: string };
    placeholders?: string[];
    released?: string[];
    hits?: Array<{ symbol: string; level: string }>;
    checked?: boolean;
  };
}

function eventId(): string {
  return `ocp-${Date.now().toString(36)}-${randomBytes(5).toString("hex")}`;
}

/** A refused tool call (the tamper policy). */
export function tamperEvent(args: {
  sessionId: string;
  sessionKey: string | null;
  agentId: string;
  toolName: string;
  toolCallId: string | null;
  rule: string;
  what: string;
}): PluginEvent {
  return {
    id: eventId(), sessionId: args.sessionId, turn: 0, ts: new Date().toISOString(), seq: 0,
    callId: args.toolCallId, parentId: null,
    kind: "tool_use", view: "AgentView", boundary: "shell", emitter: "openclaw-plugin",
    input: null, output: null,
    policy: { usage: "deny", reason: `refused: names ${args.what}`, ruleRef: { source: "rule", id: `openclaw:tamper:${args.rule}` } },
    invariant: { violatedInvariant: false },
    openclaw: { sessionKey: args.sessionKey, agentId: args.agentId, toolName: args.toolName },
  };
}

/** What happened to one outgoing reply that carried placeholders or tripped. */
export function replyEvent(args: {
  sessionId: string;
  sessionKey: string | null;
  agentId: string;
  destination: { channel: string; accountId?: string; conversationId?: string; to: string };
  outcome: "kept" | "released" | "cancelled";
  placeholders: string[];
  released?: string[];
  hits?: Array<{ symbol: string; level: string }>;
  /** False when the tripwire could not run (the arbiter was unreachable). */
  checked: boolean;
}): PluginEvent {
  const reason = args.outcome === "cancelled"
    ? "reply cancelled: it carried a protected value no rule allows to this chat"
    : args.outcome === "released"
      ? "values put back where a rule binds this chat"
      : "placeholders kept: no rule binds this chat";
  return {
    id: eventId(), sessionId: args.sessionId, turn: 0, ts: new Date().toISOString(), seq: 0,
    callId: null, parentId: null,
    kind: "egress_decision", view: "HumanView", boundary: "network", emitter: "openclaw-plugin",
    input: null, output: null,
    policy: {
      usage: args.outcome === "cancelled" ? "deny" : "allow",
      reason,
      ruleRef: args.outcome === "cancelled"
        ? { source: "rule", id: "openclaw:reply:fingerprint" }
        : args.outcome === "released"
          ? { source: "rule", id: "openclaw:reply:bound" }
          : { source: "fail-closed", id: "openclaw:reply:unbound" },
    },
    invariant: { violatedInvariant: false },
    openclaw: {
      sessionKey: args.sessionKey, agentId: args.agentId, destination: args.destination,
      placeholders: args.placeholders,
      ...(args.released ? { released: args.released } : {}),
      ...(args.hits ? { hits: args.hits } : {}),
      checked: args.checked,
    },
  };
}
