/**
 * policy-tool — the trust rule for the Mandu POLICY tools' results
 * (docs/design/ui/policy-surface.md §8.4.4, §8.5.1). Mandu-new.
 *
 * `interceptors/policy-mcp` is part of the Mandu TCB: it lets the confined
 * agent read the law, test a flow, and propose edits. Its results come back
 * to T-LLM as MCP tool_results, which the blanket `mcp__*` rule classifies
 * UNTRUSTED and symbolizes whole, which would leave the agent unable to read
 * the answer at all. This module is the one exception for those three tools,
 * built exactly like the inspect rule (claude-code-inbound.ts, "WHY NOT
 * name-only" / "WHY NOT shape-only"): a result is TRUSTED iff BOTH
 *
 *   (1) NAME: the tool name is one of the spellings Mandu's own mount
 *       produces (`mcp__mandu-policy__<tool>` on Claude Code,
 *       `mandu-policy_<tool>` on OpenCode, `mandu-policy__<tool>` on Goose, `mcp__mandu_policy__<tool>`
 *       on Codex, as the openai-proxy names a namespaced call). No bare spelling: OpenClaw has
 *       no policy plugin, so nothing may claim one; and
 *   (2) SHAPE: the whole value is ONE JSON object whose top-level `tool`
 *       names that same tool, and in which every string (keys and values) is
 *       a bounded TOKEN (no whitespace, a path/host/URL character set, at most
 *       200 characters) or EXACTLY one of the fixed messages below. The one
 *       prose channel is the top-level `problems` array of an `invalid` or
 *       `stale` propose answer: single lines of at most 300 characters with no
 *       angle brackets (no tag forgery).
 *
 * WHAT CAN REACH THOSE STRINGS (the audit this rule rests on):
 *   - the law (policy.yaml, mandu.db labels): a human wrote it, or approved
 *     the proposal that wrote it;
 *   - the agent's OWN proposals (subjects of its edits): T-LLM output;
 *   - arbiter-minted ids (`pp-…`, `pc-…`, rule ids) and enums;
 *   - validator problems: arbiter templates over the law and the agent's own
 *     edits (the only prose, bounded as above).
 * What CANNOT: tool-result bodies, symbol values, event text, any `reason`,
 * and the hosts of pending egress asks (a page can choose those): the agent
 * audience of `policyExplain` carries a COUNT of asks, never their hosts, and
 * only this session's own proposals.
 *
 * Anything else under these names (an error string, a missing `tool`, prose
 * in a field, a mismatched tool) fails closed to UNTRUSTED and is symbolized.
 * interceptors/policy-mcp/src carries byte-identical copies of the messages
 * with a DO-NOT-DRIFT note; the integration parity test runs every envelope
 * the real server builds through {@link classifyManduPolicyResult}.
 */

/** The MCP server id Mandu mounts the policy tools under. */
export const MANDU_POLICY_SERVER = "mandu-policy";

export const POLICY_TOOL_BASENAMES = ["mandu_policy_read", "mandu_policy_test", "mandu_policy_propose"] as const;
export type PolicyToolBasename = (typeof POLICY_TOOL_BASENAMES)[number];

const SPELLING_TO_BASENAME: ReadonlyMap<string, PolicyToolBasename> = new Map(
  POLICY_TOOL_BASENAMES.flatMap((b) => [
    [`mcp__${MANDU_POLICY_SERVER}__${b}`, b] as const, // Claude Code
    [`${MANDU_POLICY_SERVER}_${b}`, b] as const, // OpenCode (single underscore)
    // Codex 0.154: {name: <tool>, namespace: "mcp__mandu_policy"} (the
    // server's "-" becomes "_"), joined by the openai-proxy with "__". Read
    // off a live codex exec against a recording Responses server, 2026-09-25.
    [`mcp__${MANDU_POLICY_SERVER.replace(/-/g, "_")}__${b}`, b] as const,
    // Goose: <extension key>__<tool>, the key as the launcher names it
    // (`--with-extension 'mandu-policy:<cmd>'`; the inspect mount's spelling
    // read off goose 1.53.0's wire, 2026-10-05).
    [`${MANDU_POLICY_SERVER}__${b}`, b] as const,
  ]),
);

/** Every recognized spelling, for tests and docs. */
export const POLICY_TOOL_SPELLINGS: readonly string[] = [...SPELLING_TO_BASENAME.keys()];

/** The basename, when `toolName` is one of Mandu's own policy tool spellings. */
export function manduPolicyToolBasename(toolName: string): PolicyToolBasename | undefined {
  return SPELLING_TO_BASENAME.get(toolName);
}

export function isManduPolicyTool(toolName: string): boolean {
  return SPELLING_TO_BASENAME.has(toolName);
}

/** The fixed messages a trusted envelope may carry. DO NOT DRIFT from
 *  interceptors/policy-mcp/src (byte-identical there). */
export const POLICY_TOOL_MESSAGES: readonly string[] = [
  "Applied: the rule is in force now. The user can undo it from the Mandu dashboard.",
  "Nothing changed: the rules already say this.",
  "Not applied: none of these edits is in force, the locks among them included. This change loosens protection, so all of it waits for the user to approve it on the Mandu dashboard's Approvals page. Propose the tightenings alone in another call to apply them now. Do not tell the user any of it is done.",
  "Not applied. You have made many changes this session, so this one is waiting for the user's approval on the Mandu dashboard's Approvals page.",
  "Already waiting: the same change is pending on the Mandu dashboard's Approvals page.",
  "Not applied: the edits are not valid. See problems, and check them against the schema in this tool's description.",
  "Not applied: the policy file changed on disk just now. Read the rules again and retry.",
  "Not applied: too many changes are already waiting for the user. Ask them to review the Mandu dashboard's Approvals page first.",
];
const MESSAGES = new Set(POLICY_TOOL_MESSAGES);

/** Same grammar as ipc/policy-agent-ops.ts `token` (policyExplain's rule). */
export const POLICY_TOKEN_RE = /^[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{1,200}$/;
const PROBLEM_RE = /^[^\n\r<>]{1,300}$/;
const MAX_BYTES = 64 * 1024;
const MAX_DEPTH = 8;

function okString(s: string): boolean {
  return POLICY_TOKEN_RE.test(s) || MESSAGES.has(s);
}

function okValue(v: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) return false;
  if (v === null || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (typeof v === "string") return okString(v);
  if (Array.isArray(v)) return v.every((x) => okValue(x, depth + 1));
  if (typeof v === "object") {
    return Object.entries(v as Record<string, unknown>).every(([k, x]) => okString(k) && okValue(x, depth + 1));
  }
  return false;
}

/** Is `value` exactly a well-formed envelope of the policy tool `basename`? */
export function isPolicyToolEnvelope(basename: PolicyToolBasename, value: string): boolean {
  if (typeof value !== "string" || value.length > MAX_BYTES) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value.trim());
  } catch {
    return false;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
  const obj = parsed as Record<string, unknown>;
  if (obj.tool !== basename) return false;
  for (const [k, v] of Object.entries(obj)) {
    if (k === "problems") {
      if (basename !== "mandu_policy_propose" || !Array.isArray(v) || v.length > 50) return false;
      if (!v.every((p) => typeof p === "string" && PROBLEM_RE.test(p))) return false;
      continue;
    }
    if (!okString(k) || !okValue(v, 1)) return false;
  }
  return true;
}

/**
 * Whole-result classification for the policy tools (the name half is the
 * caller's `isManduPolicyTool`; checked again here). The return shape
 * mirrors policy-interface.ts ClassifyResult structurally.
 */
export function classifyManduPolicyResult(toolName: string, value: string): {
  trust: "TRUSTED" | "UNTRUSTED";
  category: null;
  reason: string;
} {
  const basename = manduPolicyToolBasename(toolName);
  if (basename && isPolicyToolEnvelope(basename, value)) {
    return {
      trust: "TRUSTED",
      category: null,
      reason: `policy tool rule: ${toolName} result is a well-formed ${basename} envelope (bounded tokens and fixed messages only)`,
    };
  }
  return {
    trust: "UNTRUSTED",
    category: null,
    reason: `fail-closed: ${toolName} result is not a well-formed policy tool envelope (an error, prose, or a spoofed server) → symbolize`,
  };
}
