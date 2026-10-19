/**
 * server-main — deployment entrypoint for the mandu-policy MCP stdio server.
 *
 * PROVENANCE: copied from interceptors/inspect-mcp/src/server-main.ts (the
 * lazy structural import of the arbiter client, the fail-closed env check,
 * the entrypoint guard), without the U-LLM wiring this server has no use for.
 *
 * The agent (Claude Code, OpenCode) spawns this from the MCP config the
 * launcher writes (launcher/src/services/mcp.ts). Env:
 *   MANDU_ARBITER_SOCK — arbiter DATA socket (required).
 *   MANDU_SCOPE_ID     — the session key: attribution and the per-session caps.
 *   MANDU_PROJECT_DIR  — the directory the session was launched in: a relative
 *                        path in a proposed edit is read there (tools.ts
 *                        `resolveEditPaths`). Absent: relative paths are refused.
 */
import { isEntrypoint } from "./entrypoint.js";

import { PolicyArbiterAdapter, type RealArbiterClient } from "./arbiter-client.js";
import { runStdioServer } from "./mcp-server.js";
import type { PolicyToolDeps } from "./tools.js";

/** The deps this server takes from its environment (the launcher's MCP
 *  config entry): the session key and the project directory, each only
 *  when set (the directory only when absolute). */
export function envDeps(env: NodeJS.ProcessEnv): Pick<PolicyToolDeps, "sessionKey" | "projectDir"> {
  const sessionKey = env.MANDU_SCOPE_ID;
  const projectDir = env.MANDU_PROJECT_DIR;
  return {
    ...(sessionKey ? { sessionKey } : {}),
    ...(projectDir && projectDir.startsWith("/") ? { projectDir } : {}),
  };
}

async function main(): Promise<void> {
  process.title = "mandu-policy-mcp";
  const sockPath = process.env.MANDU_ARBITER_SOCK;
  if (!sockPath) fail("MANDU_ARBITER_SOCK is not set; cannot reach the arbiter (fail closed).");
  const client = await loadArbiterClient(sockPath!);
  await client.connect();
  runStdioServer({ arbiter: new PolicyArbiterAdapter(client), ...envDeps(process.env) });
  process.stdin.on("close", () => client.close());
}

/** Kept out of the static import graph so this package builds without the
 *  sibling arbiter; the installed bundle inlines it (same as inspect-mcp). */
async function loadArbiterClient(sockPath: string): Promise<RealArbiterClient> {
  const mod = (await import(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    "../../../arbiter/ipc/client.js" as any
  )) as { ArbiterClient: new (sock: string) => RealArbiterClient };
  return new mod.ArbiterClient(sockPath);
}

function fail(message: string): never {
  process.stderr.write(`[policy-mcp] ${message}\n`);
  process.exit(1);
}

// Realpath-aware (src/entrypoint.ts): a symlinked spelling of this file
// (darwin's /tmp → /private/tmp) still starts the server.
if (isEntrypoint(import.meta.url, process.argv[1])) {
  main().catch((err) => {
    process.stderr.write(`[policy-mcp] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
