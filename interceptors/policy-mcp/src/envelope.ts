/**
 * envelope — the ONLY shape a successful mandu-policy tool result may take
 * (docs/design/ui/policy-surface.md §8.5.1, §8.4.4).
 *
 * Mandu-new (no reference origin). The result of an MCP tool reaches the
 * privileged model as a tool_result, and the anthropic-proxy classifies every
 * `mcp__*` result UNTRUSTED (masked) by default. The arbiter trusts this
 * server's results only through an exact-name + shape gate
 * (arbiter/policy/policy-tool.ts, `classifyManduPolicyResult`), mirroring
 * the inspect tool's hybrid rule. The shape is:
 *
 *   one text content item = JSON.stringify(envelope), no structuredContent;
 *   the envelope is an object whose top-level "tool" is the tool basename;
 *   recursively every string (keys and values) is a TOKEN (no whitespace, a
 *   path/host/URL character set, 1..200 chars) or one of FIXED_MESSAGES;
 *   numbers, booleans and null are allowed; depth ≤ 8; ≤ 64 KB;
 *   the ONE exception: the propose tool's top-level "problems" array (≤ 50
 *   non-empty lines) may carry prose, each ≤ 300 chars, no newline, no '<' or '>'.
 *
 * So nothing here can carry an instruction channel: no free text reaches the
 * model except the fixed messages this file owns and the arbiter validator's
 * problem lines (templates over the human's law and the agent's own edits).
 *
 * DO-NOT-DRIFT: FIXED_MESSAGES, TOKEN_RE, the limits and the "problems"
 * exception are mirrored byte-for-byte by arbiter/policy/policy-tool.ts. A
 * change here without the same change there makes every result of this tool
 * fall back to the fail-closed mask (safe, useless); a change THERE that
 * accepts more than this file emits widens the trust surface for nothing.
 */

/** The fixed messages a result may carry. Byte-identical to the arbiter gate. */
export const FIXED_MESSAGES = {
  applied: "Applied: the rule is in force now. The user can undo it from the Mandu dashboard.",
  noChange: "Nothing changed: the rules already say this.",
  pendingRelax:
    "Not applied: none of these edits is in force, the locks among them included. This change loosens protection, so all of it waits for the user to approve it on the Mandu dashboard's Approvals page. Propose the tightenings alone in another call to apply them now. Do not tell the user any of it is done.",
  pendingCap:
    "Not applied. You have made many changes this session, so this one is waiting for the user's approval on the Mandu dashboard's Approvals page.",
  duplicate: "Already waiting: the same change is pending on the Mandu dashboard's Approvals page.",
  invalid: "Not applied: the edits are not valid. See problems, and check them against the schema in this tool's description.",
  stale: "Not applied: the policy file changed on disk just now. Read the rules again and retry.",
  proposalCap: "Not applied: too many changes are already waiting for the user. Ask them to review the Mandu dashboard's Approvals page first.",
} as const;

export type FixedMessage = (typeof FIXED_MESSAGES)[keyof typeof FIXED_MESSAGES];

const FIXED_SET: ReadonlySet<string> = new Set(Object.values(FIXED_MESSAGES));

export const TOKEN_RE = /^[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{1,200}$/;
export const WITHHELD = "(withheld)";
export const MAX_DEPTH = 8;
export const MAX_BYTES = 64 * 1024;
export const PROBLEM_MAX = 300;
/** At most this many problem lines (the gate refuses more). */
export const PROBLEMS_MAX = 50;
export const TOOL_NAMES = ["mandu_policy_read", "mandu_policy_test", "mandu_policy_propose"] as const;
export type PolicyToolName = (typeof TOOL_NAMES)[number];

/** A string the envelope may carry as-is, or WITHHELD. */
export function token(v: string): string {
  return TOKEN_RE.test(v) || FIXED_SET.has(v) ? v : WITHHELD;
}

/** One problem line: clipped, one line, no angle brackets. */
export function clipProblem(p: string): string {
  const flat = String(p).replace(/[\r\n]+/g, " ").replace(/[<>]/g, "");
  return flat.length > PROBLEM_MAX ? flat.slice(0, PROBLEM_MAX - 1) + "…" : flat;
}

/**
 * Recursively rewrite a value so every string (key or value) is a token or a
 * fixed message; anything deeper than MAX_DEPTH, and any non-JSON value,
 * becomes WITHHELD/null. Keys that are not tokens are dropped (a key cannot
 * become "(withheld)" twice in one object).
 */
export function sanitize(v: unknown, depth = 0): unknown {
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string") return token(v);
  if (depth >= MAX_DEPTH) return null;
  if (Array.isArray(v)) return v.map((x) => sanitize(x, depth + 1));
  if (typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (x === undefined || !TOKEN_RE.test(k)) continue;
      out[k] = sanitize(x, depth + 1);
    }
    return out;
  }
  return null;
}

/** The envelope as the one text content item of a successful tools/call. */
export function toolResult(envelope: Record<string, unknown>): { content: [{ type: "text"; text: string }]; isError: false } {
  const { problems, ...rest } = envelope;
  const clean = sanitize(rest) as Record<string, unknown>;
  if (Array.isArray(problems)) {
    clean.problems = problems.map((p) => clipProblem(String(p))).filter((p) => p.trim() !== "").slice(0, PROBLEMS_MAX);
  }
  let text = JSON.stringify(clean);
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) {
    // Never emit a shape the gate would refuse: shrink to the bare envelope.
    text = JSON.stringify({ tool: clean.tool, truncated: true });
  }
  return { content: [{ type: "text", text }], isError: false };
}

/** A local copy of the gate's grammar, used by this package's tests. */
export function satisfiesGrammar(text: string, toolName: string): boolean {
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) return false;
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return false;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const top = v as Record<string, unknown>;
  if (top.tool !== toolName) return false;
  const walk = (x: unknown, depth: number): boolean => {
    if (depth > MAX_DEPTH) return false;
    if (x === null || typeof x === "boolean" || typeof x === "number") return true;
    if (typeof x === "string") return TOKEN_RE.test(x) || FIXED_SET.has(x);
    if (Array.isArray(x)) return x.every((y) => walk(y, depth + 1));
    if (typeof x === "object") return Object.entries(x as object).every(([k, y]) => TOKEN_RE.test(k) && walk(y, depth + 1));
    return false;
  };
  for (const [k, x] of Object.entries(top)) {
    if (!TOKEN_RE.test(k)) return false;
    if (k === "problems") {
      if (toolName !== "mandu_policy_propose" || !Array.isArray(x) || x.length > PROBLEMS_MAX) return false;
      if (!x.every((p) => typeof p === "string" && p.length >= 1 && p.length <= PROBLEM_MAX && !/[\r\n<>]/.test(p))) return false;
      continue;
    }
    if (!walk(x, 1)) return false;
  }
  return true;
}
