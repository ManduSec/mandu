// GENERATED FILE: do not edit. Source: scripts/agents/agent-registry.mjs
// (docs/design/agents/supported-agents.md §5.7). Regenerate with
// `node scripts/agents/agent-copies.mjs generate`; tests/stack/agent-registry.test.ts fails when
// this copy differs from the table.

/** An agent (each agent's first line). */
export type Agent = "claude" | "codex" | "openclaw" | "opencode" | "goose";
/** An agent line: an agent, or a later generation of one. */
export type AgentLine = "claude" | "codex" | "openclaw" | "opencode" | "opencode2" | "goose";
/** An agent whose live runs take the Anthropic API key. */
export type ApiKeyAgent = "openclaw" | "opencode" | "goose";
/** An agent, and a line, on the Anthropic wire. */
export type AnthropicWireAgent = "claude" | "openclaw" | "opencode" | "goose";
export type AnthropicWireLine = "claude" | "openclaw" | "opencode" | "opencode2" | "goose";

export interface AgentLineRow {
  id: AgentLine;
  agent: Agent;
  name: string;
  generation?: number;
  wire: "anthropic" | "openai";
  credential: "subscription" | "api-key";
  signIn?: string;
  cache: boolean;
  pin: string;
  npm?: string;
}

export declare const AGENT_LINES: readonly AgentLineRow[];
export declare const LINES: readonly ["claude", "codex", "openclaw", "opencode", "opencode2", "goose"];
export declare const AGENTS: readonly ["claude", "codex", "openclaw", "opencode", "goose"];
export declare const AGENT_NAMES: Readonly<Record<Agent, string>>;
export declare const LINE_NAMES: Readonly<Record<AgentLine, string>>;
export declare const PIN_KEYS: Readonly<Record<AgentLine, string>>;
export declare const API_KEY_AGENTS: readonly ["openclaw", "opencode", "goose"];
export declare const CACHED_LINES: readonly ["openclaw", "opencode", "opencode2", "goose"];
export declare const ANTHROPIC_WIRE_AGENTS: readonly ["claude", "openclaw", "opencode", "goose"];
export declare const ANTHROPIC_WIRE_LINES: readonly ["claude", "openclaw", "opencode", "opencode2", "goose"];
export declare const NPM_AGENTS: readonly ["claude", "codex", "openclaw", "opencode"];
export declare const SIGN_IN_AGENTS: Readonly<Record<string, Agent>>;
export declare function lineOf(id: string): AgentLineRow | undefined;
export declare function agentOfLine(id: AgentLine): Agent;
export declare function agentOfLine(id: string): string;
export declare function isAgent(s: unknown): s is Agent;
export declare function isLine(s: unknown): s is AgentLine;
export declare function tableProblems(lines?: readonly AgentLineRow[]): string[];
