/**
 * session-health — the per-session HEALTH verdict (dashboard.md §4.21).
 *
 * The launcher, the reply-filter and the proxies each put on the record what
 * posture a session ACTUALLY runs at (`launch_posture`, `relay_mode`,
 * `client_info`, `tool_surface`, `session_exit`, event-model.ts). This module
 * folds those, plus the conversation itself, into one verdict the session
 * list can show as a chip:
 *
 *   ok        launched at the full posture, relay in pty/pipe, turns flowed,
 *             every advertised tool known, no command that could not run
 *   degraded  something is thinner than the product default but the session
 *             works: a dropped rung, an unknown tool, a command that could
 *             not run
 *   broken    the session cannot be doing its job: the relay is PASSTHROUGH
 *             (symbols stay opaque on the human terminal), or its last record
 *             says the arbiter did not resolve a placeholder (`relay_mode`
 *             with `resolveFailure`: the reply filter runs, its lookups
 *             fail; reply-row-reservation.md §18), or it launched but
 *             never completed a turn, or every command run failed
 *   null      not a launcher session (no launch_posture) — a proxy-only or
 *             test-harness trace; nothing to grade
 *
 * "A command that could not run" is the shape found live 2026-09-05: `Exit
 * code 126` / `bwrap: …` / `command not found` in a tool result — the agent
 * keeps running while nothing it runs works. A result's tool is found by its
 * call (the proxies' `tool_result` and `symbolize` events carry no tool
 * name, 2026-10-07), and only a command tool's results are read
 * (tool-family.ts). Pure; unit-tested.
 */
import type { ManduEvent } from "./event-model.js";
import { checkAgentVersion, isVersionedAgent, previewLineOf, rangeWords, type AgentVersionCheck } from "./agent-versions.js";
import { extractToolUses } from "./view-model/tool-calls.js";
import { toolFamily } from "./view-model/tool-family.js";

export type HealthVerdict = "ok" | "degraded" | "broken";

export interface SessionHealth {
  verdict: HealthVerdict;
  /** Rungs the launcher reported LIVE (names). */
  live: string[];
  /** Launcher banner lines for dropped / degraded rungs. */
  dropped: string[];
  /** The reply-filter's mode, or null when it never reported. */
  relay: "pty" | "pipe" | "passthrough" | null;
  /** Why the reply filter's lookups fail, when its LAST record says they do
   *  (`relay_mode.resolveFailure`); absent while they resolve. */
  relayFailure?: string;
  /** The agent CLI's version as seen on its first model request. */
  clientVersion: string | null;
  /** Advertised tool names the active inbound spec does not know. */
  unknownTools: string[];
  /** The agent's version against Mandu's tested range (agent-versions.ts):
   *  from the proxy's `client_info` when it reported one, else the launcher's
   *  own probe on `launch_posture`. null when neither says. Outside the range
   *  degrades the verdict (supported-agents.md). */
  agentVersion: AgentVersionCheck | null;
  /** The label of the PREVIEW line that version belongs to ("Goose",
   *  "OpenCode 2"; supported-agents.md §2.0), from the dashboard's own
   *  table; absent for a supported agent or no version check. A note, never
   *  a downgrade: the status is about how much testing stands behind the
   *  agent, not about what Mandu enforces. */
  preview?: string;
  /** Conversation-class model calls (a tool battery + a delivered reply). */
  turns: number;
  /** Command runs (calls in tool-family.ts's `exec` family) whose result
   *  says the command could not execute, one per call. The name predates
   *  the check reading only command tools; the copy says "command"
   *  (dashboard.md §4.21). */
  toolFailures: number;
  /** The agent's exit code, once it exited. */
  exitCode: number | null;
  /** One-line reasons behind a non-ok verdict, and notes that grade
   *  nothing (an unreadable version, a preview agent), for the chip's tooltip. */
  reasons: string[];
  /** The secret-confinement posture the launcher recorded
   *  (launcher/src/confinement-posture.ts; rootless-confinement-ubuntu-2404.md
   *  §3.4): confined / read-blocked / gated. Absent when the confidentiality
   *  axis was off or the launcher predates the field. `gated` is a KNOWN HOST
   *  CONDITION: it degrades the verdict (amber), never breaks it (red). */
  secrets?: SecretsPosture;
}

export interface SecretsPosture {
  posture: "confined" | "read-blocked" | "gated";
  /** Why gated: a host gap code, or "arbiter". */
  gap?: string;
  /** The one honest sentence for this posture. */
  sentence: string;
  /** The upgrade command, when one exists for this gap. */
  fix?: string;
}

/** Mirrors launcher/src/confinement-posture.ts POSTURE_SENTENCE / gapExplanation
 *  (the dashboard does not import the launcher package; the parity test in
 *  test/unit/session-health.test.ts holds the two equal). */
export const SECRETS_SENTENCE: Record<SecretsPosture["posture"], string> = {
  "confined": "Programs the AI runs get a placeholder copy of each credential file, never the real one. A program you allow to read a file gets the real contents, and what it prints is masked before the AI sees it.",
  "read-blocked": "Programs the AI runs cannot open your credential files: a read fails instead of returning a placeholder.",
  "gated": "The AI sees placeholders and a secret is sent out only where a rule or your OK allows, but programs the AI runs can still read your credential files.",
};
export const SECRETS_FIX: Record<string, string> = {
  "apparmor-userns": "mandu setup",
  "no-bwrap": "sudo apt install bubblewrap",
  "bwrap-nesting": "mandu setup",
  // "no-guard" / "guard-off" (the mount layer alone, no file guard) carry no
  // one-command fix: the cause line in the launch notice says what to do.
};

/** The bind-only gaps (sandbox-security-review-2026-09-28 finding 7): the
 *  mount layer is up, so the tooltip says what it covers and what it misses. */
export const SECRETS_PARTIAL_NOTE: Record<string, string> = {
  "no-guard": "The mount layer still puts a placeholder over each credential file, but Mandu's file guard is not available, so a file replaced while the AI runs is readable.",
  "guard-off": "The mount layer still puts a placeholder over each credential file, but Mandu's file guard is turned off, so a file replaced while the AI runs is readable.",
};

function secretsOf(posture: Record<string, unknown>): SecretsPosture | undefined {
  const raw = posture["secrets"] as { posture?: unknown; gap?: unknown } | undefined;
  if (!raw || (raw.posture !== "confined" && raw.posture !== "read-blocked" && raw.posture !== "gated")) return undefined;
  const gap = typeof raw.gap === "string" ? raw.gap : undefined;
  const fix = gap !== undefined ? SECRETS_FIX[gap] : undefined;
  return { posture: raw.posture, sentence: SECRETS_SENTENCE[raw.posture], ...(gap ? { gap } : {}), ...(fix ? { fix } : {}) };
}

/** The session's agent version check: the proxy's `client_info` version (the
 *  agent as it identified itself on the wire; Claude Code only) wins over the
 *  launcher's `--version` probe, which covers the agents no proxy reports. */
function versionCheckOf(posture: Loose, clientVersion: string | null): AgentVersionCheck | null {
  const target = posture["target"];
  if (!isVersionedAgent(target)) return null;
  if (clientVersion !== null && target === "claude") return checkAgentVersion(target, clientVersion);
  const probed = posture["agentVersion"] as { agent?: unknown; version?: unknown } | undefined;
  if (!probed || probed.agent !== target) return null;
  return checkAgentVersion(target, typeof probed.version === "string" ? probed.version : null);
}

/** A tool output that says the COMMAND could not run (not that it ran and
 *  failed the task): exec shim / sandbox / lookup failures. Exit 126 / 127
 *  as each agent's runtime heads the output: Claude Code's `Exit code 126`,
 *  Codex's classic shell `Exit code: 126`, its unified exec `Process exited
 *  with code 126` (agent-result-head.ts) and its script cell `Script failed
 *  (exit code 126)`. */
export const TOOL_CANNOT_RUN_RE =
  /^(?:Exit code:? |Process exited with code |Script failed \(exit code )(?:126|127)\b|bwrap: |command not found|Failed to create NETLINK|Can't mount proc|Operation not permitted/m;

type Loose = ManduEvent & Record<string, unknown>;

export function deriveHealth(events: readonly ManduEvent[]): SessionHealth | null {
  const posture = events.find((e) => e.kind === "launch_posture") as Loose | undefined;
  if (!posture) return null;

  const live = Array.isArray(posture["live"]) ? (posture["live"] as unknown[]).filter((x): x is string => typeof x === "string") : [];
  const dropped = Array.isArray(posture["dropped"]) ? (posture["dropped"] as unknown[]).filter((x): x is string => typeof x === "string") : [];

  const relayEv = [...events].reverse().find((e) => e.kind === "relay_mode") as Loose | undefined;
  const relay = relayEv && typeof relayEv["mode"] === "string" ? (relayEv["mode"] as SessionHealth["relay"]) : null;
  const relayFailure = relayEv && typeof relayEv["resolveFailure"] === "string" ? (relayEv["resolveFailure"] as string) : undefined;

  const info = events.find((e) => e.kind === "client_info") as Loose | undefined;
  const clientVersion = info && typeof info["clientVersion"] === "string" ? (info["clientVersion"] as string) : null;

  const agentVersion = versionCheckOf(posture, clientVersion);
  const preview = agentVersion ? previewLineOf(agentVersion.agent, agentVersion.version) : null;

  const surface = events.find((e) => e.kind === "tool_surface") as Loose | undefined;
  const unknownTools = surface && Array.isArray(surface["unknown"])
    ? (surface["unknown"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];

  // A conversation turn: a T-LLM call that carried the tool battery and
  // delivered prose (side calls — quota probe, title, typeahead — carry no
  // battery or no prose; a tool-use decision is mid-loop, not a turn).
  let turns = 0;
  // Tool runs that could not execute: ONLY command-tool outputs are scanned
  // (a secret twin's or a file's bytes may legitimately contain "command not
  // found"), and one failing CALL counts once however many events carry it.
  // The proxies record a result with its call id only, so its tool is the
  // one its call named (the `tool_use` event, else the transcript's
  // `→ Name(…)` line); an event that names its own tool keeps it. The calls
  // are read only once a result reads like a failure: the session list
  // grades every session, and most have none.
  let calls: ReturnType<typeof extractToolUses> | null = null;
  const toolOf = (e: ManduEvent): string => {
    const own = (e as Loose)["tool"];
    if (typeof own === "string") return own;
    if (!e.callId) return "";
    calls ??= extractToolUses(events);
    return calls.get(e.callId)?.tool ?? "";
  };
  const failedCalls = new Set<string>();
  for (const e of events) {
    if (e.kind === "tllm_call") {
      const shape = (e as Loose)["callShape"] as { toolCount?: number } | undefined;
      const out = e.output?.symbolized ?? "";
      if ((shape?.toolCount ?? 0) > 0 && out !== "" && !/^\s*→ /m.test(out)) turns++;
    }
    if (e.kind === "tool_result" || e.kind === "symbolize") {
      const key = e.callId ?? e.id;
      if (failedCalls.has(key)) continue;
      const text = e.input?.original ?? e.output?.original ?? e.input?.symbolized ?? e.output?.symbolized ?? "";
      if (typeof text !== "string" || !TOOL_CANNOT_RUN_RE.test(text)) continue;
      if (toolFamily(toolOf(e)) === "exec") failedCalls.add(key);
    }
  }
  const toolFailures = failedCalls.size;

  const exitEv = [...events].reverse().find((e) => e.kind === "session_exit") as Loose | undefined;
  const exitCode = exitEv && typeof exitEv["code"] === "number" ? (exitEv["code"] as number) : null;

  const reasons: string[] = [];
  let verdict: HealthVerdict = "ok";
  const degrade = (why: string): void => { reasons.push(why); if (verdict === "ok") verdict = "degraded"; };
  const breakIt = (why: string): void => { reasons.push(why); verdict = "broken"; };

  // The gated notice is a multi-line banner; the chip's tooltip gets the one
  // honest sentence + the fix instead, and the verdict is amber, never red.
  const secrets = secretsOf(posture);
  for (const d of dropped) {
    if (secrets?.posture === "gated" && /secrets are GATED/.test(d)) continue;
    degrade(d);
  }
  if (secrets?.posture === "gated") {
    const partial = secrets.gap !== undefined ? SECRETS_PARTIAL_NOTE[secrets.gap] : undefined;
    degrade(`secrets are gated, not confined: ${secrets.sentence}${partial ? ` ${partial}` : ""}${secrets.fix ? ` Upgrade once with \`${secrets.fix}\`.` : ""}`);
  }
  if (unknownTools.length) degrade(`tools with no inbound spec (outputs fail closed): ${unknownTools.join(", ")}`);
  if (agentVersion?.verdict === "newer" || agentVersion?.verdict === "older") {
    degrade(`${agentVersion.name} ${agentVersion.version} is ${agentVersion.verdict} than the tested range (${rangeWords(agentVersion)}); tools it adds fail closed until mapped`);
  } else if (agentVersion?.verdict === "unknown") {
    reasons.push(`the launcher could not read the ${agentVersion.name} version (tested: ${rangeWords(agentVersion)})`);
  }
  if (preview !== null) reasons.push(`${preview} support is a preview: tested less than Claude Code and Codex`);
  if (relay === "passthrough") breakIt("reply-filter in PASSTHROUGH: symbols stay opaque on the terminal");
  else if (relayFailure !== undefined) breakIt(`reply-filter cannot resolve placeholders (${relayFailure}): symbols stay opaque on the terminal`);
  const modelCalls = events.filter((e) => e.kind === "tllm_call").length;
  if (exitEv && modelCalls > 0 && turns === 0) breakIt("the agent made model calls but never completed a conversation turn");
  // No model call at all: a `--version` / quit-at-the-prompt launch is normal
  // (exit 0, nothing to grade); a non-zero exit with no model call is the
  // agent dying before its first request — broken.
  if (exitEv && modelCalls === 0) {
    if (exitCode !== null && exitCode !== 0) breakIt(`the agent exited ${exitCode} without a single model call`);
    else reasons.push("no model call in this session (a --version or quit-only launch)");
  }
  if (toolFailures > 0) {
    const ran = events.filter((e) => e.kind === "exec_action").length;
    if (ran > 0 && toolFailures >= ran) breakIt(`every command run (${ran}) could not execute`);
    else degrade(`${toolFailures} command ${toolFailures === 1 ? "run" : "runs"} could not execute (exit 126/127, sandbox or lookup failure)`);
  }

  return {
    verdict, live, dropped, relay, clientVersion, unknownTools, agentVersion, turns, toolFailures, exitCode, reasons,
    ...(secrets ? { secrets } : {}),
    ...(relayFailure !== undefined ? { relayFailure } : {}),
    ...(preview !== null ? { preview } : {}),
  };
}
