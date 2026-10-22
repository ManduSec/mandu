/**
 * session-logins — the AI agents' login files THIS session leaves raw, which
 * the egress tripwire must not refuse in it (secret-discovery.md §1.10, "In
 * the session that runs the agent").
 *
 * A launch that does not run an agent registers that agent's login file
 * (`~/.codex/auth.json` under `mandu claude`, `~/.claude.json` under `mandu
 * codex`), and registration is global and durable: the values stay known to
 * the arbiter after that launch ends. The session that DOES run the agent
 * reads the file raw and sends its token to its own services (a ChatGPT
 * login's bearer to chatgpt.com and its refresh to auth.openai.com, Claude
 * Code's OAuth refresh, the MCP servers' tokens in `~/.claude.json`): the
 * §4 tripwire, scanning every request for registered values, would refuse
 * them. So the launcher tells this proxy which agents' logins its session
 * keeps (the walk's keying: the launched agent and the AI helper's CLI, or
 * every agent's under MANDU_OTHER_AGENT_LOGINS=raw, with HOME and the
 * variables that move a login), and the proxy sends it with every tripwire
 * scan; the arbiter leaves those login files' registered rows out of that
 * scan only (`sessionLoginPaths`: login files, never another path).
 *
 * Carried in MANDU_NET_PROXY_SESSION_LOGINS as JSON. Absent or malformed:
 * nothing is exempt (the strict direction: the tripwire fires as it did).
 * Published in the identity, so a launch never adopts a proxy started for
 * another session's logins.
 *
 * Mandu-new (no reference origin).
 */

/** The variable carrying the session's logins (JSON). */
export const SESSION_LOGINS_ENV = "MANDU_NET_PROXY_SESSION_LOGINS";

/** Mirrors arbiter/ipc/protocol.ts `SessionLoginsWire` (secret-discovery.ts
 *  `SessionLogins`). */
export interface SessionLogins {
  home: string;
  target?: string;
  ullmBinary?: string;
  otherLoginsRaw?: boolean;
  loginEnv?: Record<string, string>;
  /** The project MCP configs the session's agent reads (secret-discovery.md
   *  §2.10, a Claude Code `.mcp.json`): absolute paths; the arbiter keeps
   *  only a config a kept agent reads. */
  mcpConfigs?: string[];
}

/** How many `mcpConfigs` are carried (the arbiter's own bound). */
const MAX_MCP_CONFIGS = 16;

/** The value of SESSION_LOGINS_ENV as a SessionLogins, or null (absent,
 *  not JSON, or no absolute `home`), with the reason for a malformed one.
 *  Unknown fields are dropped; `loginEnv` keeps string values only (the
 *  arbiter keeps its known names with absolute values); `mcpConfigs` keeps
 *  absolute paths only. Pure. */
export function parseSessionLogins(raw: string | undefined): { logins: SessionLogins | null; error?: string } {
  if (raw === undefined || raw.trim() === "") return { logins: null };
  let v: unknown;
  try { v = JSON.parse(raw); } catch (e) { return { logins: null, error: `not JSON (${(e as Error).message})` }; }
  if (v === null || typeof v !== "object" || Array.isArray(v)) return { logins: null, error: "not an object" };
  const o = v as Record<string, unknown>;
  if (typeof o["home"] !== "string" || !o["home"].startsWith("/")) return { logins: null, error: "no absolute home" };
  const env: Record<string, string> = {};
  if (o["loginEnv"] !== null && typeof o["loginEnv"] === "object" && !Array.isArray(o["loginEnv"])) {
    for (const [k, val] of Object.entries(o["loginEnv"] as Record<string, unknown>)) if (typeof val === "string") env[k] = val;
  }
  const mcp = Array.isArray(o["mcpConfigs"])
    ? (o["mcpConfigs"] as unknown[]).filter((p): p is string => typeof p === "string" && p.startsWith("/")).slice(0, MAX_MCP_CONFIGS)
    : [];
  return {
    logins: {
      home: o["home"],
      ...(typeof o["target"] === "string" && o["target"] !== "" ? { target: o["target"] } : {}),
      ...(typeof o["ullmBinary"] === "string" && o["ullmBinary"] !== "" ? { ullmBinary: o["ullmBinary"] } : {}),
      ...(o["otherLoginsRaw"] === true ? { otherLoginsRaw: true } : {}),
      ...(Object.keys(env).length > 0 ? { loginEnv: env } : {}),
      ...(mcp.length > 0 ? { mcpConfigs: mcp } : {}),
    },
  };
}
