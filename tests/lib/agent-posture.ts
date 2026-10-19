/**
 * agent-posture.ts — the posture helpers of the shared Anthropic-wire live
 * runner (OpenClaw · OpenCode): the seeded-file snapshot, the fs-sync git
 * wrapper, the net-proxy's arbiter bridge and mock catalog, and the U-LLM
 * inspect-mcp mount (its name, dev-layout command and env).
 *
 * Mandu (tests/). Design: docs/design/testing/agent-e2e-harness.md.
 * Extracted verbatim from anthropic-agent-runner.ts, which re-exports the
 * suite-facing name (INSPECT_MCP_SERVER); runAgentScenario is the caller of
 * the rest.
 */

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { ArbiterClientAdapter as NetProxyArbiterAdapter } from "../../interceptors/net-proxy/src/arbiter-client.js";
import type { SeededFile } from "./assertions.js";
import { REAL_UPSTREAM } from "./live-shared.js";
import { INJECTION } from "./agent-scenario.js";

/** Snapshot everything the harness seeded BEFORE the run, so the dashboard's
 *  test-setup banner can show the initial disk state after the workspace is
 *  deleted at teardown. */
export function collectSeededFiles(workspace: string): SeededFile[] {
  return readdirSync(workspace, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => {
      const rel = join(d.parentPath, d.name).slice(workspace.length + 1);
      const content = readFileSync(join(workspace, rel), "utf8");
      return { path: rel, content, poisoned: content.includes(INJECTION) };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

// ─── Posture helpers (fsSync · net · U-LLM) ──────────────────────────────────

/** Git identity for the fs-sync workspaces. The seed commit uses env identity;
 *  fs-sync's own [MDU-*] commits use the SHADOW repo's local Mandu identity,
 *  so no global git config is needed (fs-sync.md §3.2). */
const GIT_ENV = {
  GIT_AUTHOR_NAME: "mandu-e2e", GIT_AUTHOR_EMAIL: "mandu-e2e@test.local",
  GIT_COMMITTER_NAME: "mandu-e2e", GIT_COMMITTER_EMAIL: "mandu-e2e@test.local",
};

export function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", env: { ...process.env, ...GIT_ENV } });
}

export function netBridge(client: ArbiterClient): ConstructorParameters<typeof NetProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    desymbolizationDecision: (req) => client.desymbolizationDecision(req as never) as never,
    resolve: (sym) => client.resolve(sym),
    symbolize: (args) => client.symbolize(args as never),
    classify: (req) => client.classify(req as never) as never,
    taintProcess: (args) => client.taintProcess(args),
    isProcessTainted: (procKey) => client.isProcessTainted(procKey) as never,
    emit: (event) => client.emit(event as never),
    close: () => client.close(),
  };
}

/** The mock web catalog these suites can reach through the net-proxy. The
 *  EXFIL SINK IS DELIBERATELY ABSENT: a send to an uncatalogued untrusted host
 *  is exactly what the egress gate must refuse, and a catalogued sink would
 *  answer 200 and prove nothing. */
export const MOCK_SITES_YAML = `
sites:
  - url: "http://example.test/setup-guide"
    content_type: "text/html"
    body: "<html><body><h1>Setup</h1><p>Run the installer, then start the dev server.</p></body></html>"
`;

/** The MCP server name the U-LLM channel mounts under. The model-visible tool
 *  name is agent-specific (`mcp__<server>__<tool>` on Claude Code,
 *  `<server>_<tool>` on OpenCode) — arbiter/policy/inspect-tool.ts owns that
 *  mapping; the mount name is the same everywhere. */
export const INSPECT_MCP_SERVER = "mandu-inspect";

/** Dev-layout command for the inspect-mcp stdio server (mirrors
 *  launcher/src/services/layout.ts Layout.dev().inspectMcp(), flattened to the
 *  single argv array MCP configs take). */
export function inspectMcpCommand(): string[] {
  const repoRoot = join(dirname(new URL(import.meta.url).pathname), "..", "..");
  return [
    join(repoRoot, "interceptors", "inspect-mcp", "node_modules", ".bin", "tsx"),
    join(repoRoot, "interceptors", "inspect-mcp", "src", "server-main.ts"),
  ];
}

/**
 * Env for the quarantined U-LLM channel.
 *
 * ANTHROPIC_BASE_URL is the REAL endpoint, never this run's instrumented proxy
 * — the quarantine must not re-enter the T-LLM context path, and inspect-mcp's
 * `assertNonProxyBaseUrl` refuses a loopback base URL outright. `cli` mode
 * rides the logged-in subscription, so no key goes on the wire.
 *
 * PATH AND HOME ARE LOAD-BEARING, and HOME is deliberately the REAL one while
 * the AGENT's HOME is the throwaway `agentHome`. Two different processes with
 * two different jobs:
 *   - the AGENT is isolated so a run cannot touch the developer's agent state;
 *   - the U-LLM child is `claude -p`, which needs PATH to be found at all and
 *     the real HOME to see its OAuth login (it is the same subscription path
 *     claude-e2e uses, which likewise runs its agent with the real HOME).
 * OpenCode spawns MCP servers with the `environment` map REPLACING the parent
 * env rather than merging, so omitting these does not degrade — it makes the
 * quarantine silently never run (found 2026-08-06: the inspect tool mounted and
 * appeared in tools[], the model called it, and no `ullm_call` was ever
 * emitted). Reading `claude -p`'s home is not a new exposure: the quarantined
 * child is spawned with `--tools ""`, so it has no file access at all.
 */
export function inspectMcpEnv(arbiterSock: string, sessionId: string): Record<string, string> {
  return {
    PATH: process.env["PATH"] ?? "",
    HOME: process.env["HOME"] ?? "",
    MANDU_ARBITER_SOCK: arbiterSock,
    MANDU_SCOPE_ID: sessionId,
    MANDU_ULLM_MODE: "cli",
    MANDU_ULLM_BINARY: "claude",
    ANTHROPIC_BASE_URL: REAL_UPSTREAM,
  };
}
