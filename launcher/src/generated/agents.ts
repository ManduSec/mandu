// GENERATED FILE: do not edit. Source: scripts/agents/agent-registry.mjs
// (docs/design/agents/supported-agents.md §5.7). Regenerate with
// `node scripts/agents/agent-copies.mjs generate`; tests/stack/agent-registry.test.ts fails when
// this copy differs from the table. The launcher ships standalone, so it
// carries a copy of the agent list rather than an import of the table.

/** The agents: agent-versions.ts VersionedAgent; types.ts Target adds `shell`. */
export const AGENTS = ["claude", "codex", "openclaw", "opencode", "goose"] as const;
export type Agent = (typeof AGENTS)[number];
/** The agent lines: an agent, or a later generation of one that runs as its
 *  own command (doctor.ts's version probes). */
export const LINES = ["claude", "codex", "openclaw", "opencode", "opencode2", "goose"] as const;
export type AgentLine = (typeof LINES)[number];

export function isAgent(s: unknown): s is Agent {
  return (AGENTS as readonly unknown[]).includes(s);
}

/** The agents only the past-sessions scan knows: Mandu does not run them,
 *  and the scan reads their sessions (`read`) or counts them (plan 17 §4). */
export const SCAN_ONLY_AGENTS = ["gemini", "copilot", "cursor"] as const;
export type ScanOnlyAgent = (typeof SCAN_ONLY_AGENTS)[number];
export const SCAN_ONLY_NAMES: Readonly<Record<ScanOnlyAgent, string>> = { gemini: "Gemini CLI", copilot: "Copilot CLI", cursor: "Cursor" };
