#!/usr/bin/env node
// scripts/agents/agent-copies.mjs — the generator of the agent registry's typed
// copies (agent-registry.mjs; docs/design/agents/supported-agents.md §5.7):
// its own declarations, which give the TypeScript importers literal types,
// and the product packages' copies (the dashboard, the launcher and the
// arbiter each ship standalone and import nothing outside their package, the
// rule mandu-paths follows).
//
//   node scripts/agents/agent-copies.mjs generate   write every copy
//   node scripts/agents/agent-copies.mjs check      exit 1 when a copy is stale
//
// tests/stack/agent-registry.test.ts runs `check`.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AGENTS, ANTHROPIC_WIRE_AGENTS, ANTHROPIC_WIRE_LINES, API_KEY_AGENTS, CACHED_LINES, LINES, NPM_AGENTS, tableProblems,
} from "./agent-registry.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SOURCE = "scripts/agents/agent-registry.mjs";
const GENERATOR = "scripts/agents/agent-copies.mjs";

const list = (xs) => xs.map((x) => JSON.stringify(x)).join(", ");
const union = (xs) => xs.map((x) => JSON.stringify(x)).join(" | ");
const tuple = (xs) => `readonly [${xs.map((x) => JSON.stringify(x)).join(", ")}]`;

function declarations() {
  return `// GENERATED FILE: do not edit. Source: ${SOURCE}
// (docs/design/agents/supported-agents.md §5.7). Regenerate with
// \`node ${GENERATOR} generate\`; tests/stack/agent-registry.test.ts fails when
// this copy differs from the table.

/** An agent (each agent's first line). */
export type Agent = ${union(AGENTS)};
/** An agent line: an agent, or a later generation of one. */
export type AgentLine = ${union(LINES)};
/** An agent whose live runs take the Anthropic API key. */
export type ApiKeyAgent = ${union(API_KEY_AGENTS)};
/** An agent, and a line, on the Anthropic wire. */
export type AnthropicWireAgent = ${union(ANTHROPIC_WIRE_AGENTS)};
export type AnthropicWireLine = ${union(ANTHROPIC_WIRE_LINES)};

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
export declare const LINES: ${tuple(LINES)};
export declare const AGENTS: ${tuple(AGENTS)};
export declare const AGENT_NAMES: Readonly<Record<Agent, string>>;
export declare const LINE_NAMES: Readonly<Record<AgentLine, string>>;
export declare const PIN_KEYS: Readonly<Record<AgentLine, string>>;
export declare const API_KEY_AGENTS: ${tuple(API_KEY_AGENTS)};
export declare const CACHED_LINES: ${tuple(CACHED_LINES)};
export declare const ANTHROPIC_WIRE_AGENTS: ${tuple(ANTHROPIC_WIRE_AGENTS)};
export declare const ANTHROPIC_WIRE_LINES: ${tuple(ANTHROPIC_WIRE_LINES)};
export declare const NPM_AGENTS: ${tuple(NPM_AGENTS)};
export declare const SIGN_IN_AGENTS: Readonly<Record<string, Agent>>;
export declare function lineOf(id: string): AgentLineRow | undefined;
export declare function agentOfLine(id: AgentLine): Agent;
export declare function agentOfLine(id: string): string;
export declare function isAgent(s: unknown): s is Agent;
export declare function isLine(s: unknown): s is AgentLine;
export declare function tableProblems(lines?: readonly AgentLineRow[]): string[];
`;
}

/** A product package's copy: the header, then `body`. Each ships standalone,
 *  so it carries a copy of the lists it needs rather than an import of the
 *  table. */
function packageCopy(pkg, body) {
  return `// GENERATED FILE: do not edit. Source: ${SOURCE}
// (docs/design/agents/supported-agents.md §5.7). Regenerate with
// \`node ${GENERATOR} generate\`; tests/stack/agent-registry.test.ts fails when
// this copy differs from the table. The ${pkg} ships standalone, so it
// carries a copy of the agent list rather than an import of the table.
${body}`;
}

function dashboardCopy() {
  return packageCopy("dashboard", `
/** The agents (event-source/registry.ts AGENT_KINDS). */
export const AGENTS = [${list(AGENTS)}] as const;
export type Agent = (typeof AGENTS)[number];
`);
}

function launcherCopy() {
  return packageCopy("launcher", `
/** The agents: agent-versions.ts VersionedAgent; types.ts Target adds \`shell\`. */
export const AGENTS = [${list(AGENTS)}] as const;
export type Agent = (typeof AGENTS)[number];
/** The agent lines: an agent, or a later generation of one that runs as its
 *  own command (doctor.ts's version probes). */
export const LINES = [${list(LINES)}] as const;
export type AgentLine = (typeof LINES)[number];

export function isAgent(s: unknown): s is Agent {
  return (AGENTS as readonly unknown[]).includes(s);
}
`);
}

function arbiterCopy() {
  return packageCopy("arbiter", `
/** The agents (policy/secret-discovery.ts: the launch targets it knows, the
 *  agents whose stores are left raw). */
export const AGENTS = [${list(AGENTS)}] as const;
export type Agent = (typeof AGENTS)[number];
`);
}

/** Each generated copy, repo-relative. */
export const COPIES = Object.freeze([
  { path: "scripts/agents/agent-registry.d.mts", render: declarations },
  { path: "dashboard/src/generated/agents.ts", render: dashboardCopy },
  { path: "launcher/src/generated/agents.ts", render: launcherCopy },
  { path: "arbiter/src/generated/agents.ts", render: arbiterCopy },
]);

export function expectedCopies() {
  return COPIES.map((c) => ({ path: c.path, text: c.render() }));
}

/** The copies under `root` that differ from what the table generates. */
export function staleCopies(root = ROOT) {
  const out = [];
  for (const c of expectedCopies()) {
    let have = null;
    try { have = readFileSync(join(root, c.path), "utf8"); } catch { /* missing */ }
    if (have !== c.text) out.push(c.path);
  }
  return out;
}

function main(argv) {
  const problems = tableProblems();
  if (problems.length > 0) {
    process.stderr.write(`agent-registry: the table is unsound:\n${problems.map((x) => `  - ${x}`).join("\n")}\n`);
    return 1;
  }
  if (argv[0] === "generate") {
    for (const c of expectedCopies()) {
      mkdirSync(dirname(join(ROOT, c.path)), { recursive: true });
      writeFileSync(join(ROOT, c.path), c.text);
      process.stdout.write(`wrote ${c.path}\n`);
    }
    return 0;
  }
  if (argv[0] === "check") {
    const stale = staleCopies();
    if (stale.length === 0) {
      process.stdout.write(`agent-registry: ${COPIES.length} copies match the table\n`);
      return 0;
    }
    process.stderr.write(`agent-registry: stale copies (run \`node ${GENERATOR} generate\`):\n${stale.map((x) => `  - ${x}`).join("\n")}\n`);
    return 1;
  }
  process.stderr.write(`usage: node ${GENERATOR} generate|check\n`);
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = main(process.argv.slice(2));
}
