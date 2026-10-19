// GENERATED FILE: do not edit. Source: scripts/agents/agent-registry.mjs
// (docs/design/agents/supported-agents.md §5.7). Regenerate with
// `node scripts/agents/agent-copies.mjs generate`; tests/stack/agent-registry.test.ts fails when
// this copy differs from the table. The arbiter ships standalone, so it
// carries a copy of the agent list rather than an import of the table.

/** The agents (policy/secret-discovery.ts: the launch targets it knows, the
 *  agents whose stores are left raw). */
export const AGENTS = ["claude", "codex", "openclaw", "opencode", "goose"] as const;
export type Agent = (typeof AGENTS)[number];
