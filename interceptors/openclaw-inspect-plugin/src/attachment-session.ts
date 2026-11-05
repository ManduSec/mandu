/**
 * attachment-session — the Mandu session an OpenClaw agent of a resident
 * Gateway is attached as (docs/design/agents/openclaw-plugin.md §3.3).
 *
 * Mandu OpenClaw plugin (interceptors/openclaw-inspect-plugin). PURE.
 *
 * A session is `openclaw:<agentId>`, one per configured OpenClaw agent: the
 * provider headers `mandu openclaw install` writes are static, so they can
 * name an agent, not a conversation. The Gateway's own sessionKey
 * (`agent:<agentId>:<channel>:…`) is recorded in the plugin's events beside
 * it, so the session page can still tell conversations apart.
 *
 * PROVENANCE: `normalizeAgentId` mirrors OpenClaw's own
 * packages/normalization-core/src/agent-id.ts (read from the published
 * 2026.10.7 package, dist/agent-id-*.mjs; the same rule in 2026.9.9): trim,
 * lower-case, every run of characters outside `[a-z0-9_-]` becomes `-`,
 * leading and trailing dashes dropped, at most 64 characters, and an id
 * with nothing left is the default agent `main`. Its output is always inside
 * the arbiter's session-id form (arbiter/policy/cache-seals.ts SESSION_RE,
 * mirrored below), so `openclaw:<id>` needs no further escaping.
 *
 * The launcher keeps a copy (launcher/src/openclaw-attach.ts) for the
 * session it routes `openclaw.json` to; tests/stack/openclaw-plugin-parity
 * holds the two equal.
 */

/** OpenClaw's default agent id (DEFAULT_AGENT_ID). */
export const DEFAULT_AGENT_ID = "main";

/** The prefix of every attachment session of an OpenClaw agent. */
export const ATTACHMENT_SESSION_PREFIX = "openclaw:";

/** The arbiter's session-id form (arbiter/policy/cache-seals.ts SESSION_RE). */
export const SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i;
const INVALID_CHARS_RE = /[^a-z0-9_-]+/g;

/** OpenClaw's agent id, canonical (see the header). */
export function normalizeAgentId(value: string | null | undefined): string {
  const trimmed = (value ?? "").trim();
  const lower = trimmed.toLowerCase();
  if (VALID_ID_RE.test(trimmed)) return lower;
  const id = lower.replace(INVALID_CHARS_RE, "-").replace(/^-+/, "").replace(/-+$/, "").slice(0, 64);
  return id === "" ? DEFAULT_AGENT_ID : id;
}

/** The attachment session of an OpenClaw agent: `openclaw:<agentId>`. */
export function attachmentSession(agentId: string | null | undefined): string {
  return `${ATTACHMENT_SESSION_PREFIX}${normalizeAgentId(agentId)}`;
}

/** The agent id inside an OpenClaw sessionKey (`agent:<agentId>:…`), or null
 *  when the key is absent or of another shape (a smoke run without a session,
 *  a plugin-defined key). */
export function agentIdOfSessionKey(sessionKey: string | null | undefined): string | null {
  if (typeof sessionKey !== "string") return null;
  const m = /^agent:([^:]+)(?::|$)/.exec(sessionKey.trim());
  return m ? normalizeAgentId(m[1]) : null;
}
