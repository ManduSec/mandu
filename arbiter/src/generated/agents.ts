// GENERATED FILE: do not edit. Source: scripts/agents/agent-registry.mjs
// (docs/design/agents/supported-agents.md §5.7). Regenerate with
// `node scripts/agents/agent-copies.mjs generate`; tests/stack/agent-registry.test.ts fails when
// this copy differs from the table. The arbiter ships standalone, so it
// carries a copy of the agent list rather than an import of the table.

/** The agents (policy/secret-discovery.ts: the launch targets it knows, the
 *  agents whose stores are left raw). */
export const AGENTS = ["claude", "codex", "openclaw", "opencode", "goose"] as const;
export type Agent = (typeof AGENTS)[number];

/** The agents only the past-sessions scan knows: Mandu does not run them,
 *  and the scan reads their sessions (`read`) or counts them (plan 17 §4). */
export const SCAN_ONLY_AGENTS = ["gemini", "copilot", "cursor"] as const;
export type ScanOnlyAgent = (typeof SCAN_ONLY_AGENTS)[number];
export const SCAN_ONLY_NAMES: Readonly<Record<ScanOnlyAgent, string>> = { gemini: "Gemini CLI", copilot: "Copilot CLI", cursor: "Cursor" };
/** Those the scan reads (the others it only counts). */
export const SCAN_READ_AGENTS = ["gemini", "copilot"] as const;
