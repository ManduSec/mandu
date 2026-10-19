/**
 * model-host-paths — the model vendors' hosts, and the few paths on them a
 * program in the agent's tree may call directly (agent-sdks.md §4, "The
 * model-host deny"; exec-routing.md §7.5).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * WHY. Every model call of a launch goes through Mandu's model proxy (the
 * agent's base URL; the SDK route and the `claude` shim for a nested CLI). A
 * Claude Code, Codex or agent-SDK child started by its full path, or with a
 * PATH that skips the shim, follows its own environment instead: with the
 * base URL removed or pointed at the vendor it dialed the model host itself,
 * and this proxy passed a model host through as a blind tunnel. So what such
 * a program had read (a registered value copied into an unlabelled file, a
 * labelled file in the `gated` posture) reached the model in clear (until
 * 2026-10-18).
 *
 * THE RULE (the maintainer's decision, 2026-10-18). On a model host, a
 * program in the agent's tree may call only the paths listed here: the
 * account, sign-in, settings and feature-flag calls the agents make there
 * directly, and the upload calls the model proxy already gates per tool.
 * Everything else is refused before any dial (an ALLOW-list, fail-closed: a
 * new endpoint breaks a feature, it never leaks). The model proxies run
 * outside the agent's tree and dial the vendor themselves, so the agent's
 * routed model calls never reach this proxy.
 *
 * The decision needs the request's path, so it is made on the legs that read
 * one: the TLS-inspected leg (a model host is then terminated like any other
 * host) and the plain-HTTP leg. Where the path cannot be read (TLS inspection
 * off), a model host is refused whole at the CONNECT (proxy.ts).
 *
 * THE EVIDENCE. Each entry names where it was read:
 *   - `cc-2.1.302`: the Claude Code 2.1.302 native build on Linux, strings of
 *     the binary (`ln().BASE_API_URL` is `https://api.anthropic.com`,
 *     `TOKEN_URL` `https://platform.claude.com/v1/oauth/token`);
 *   - `codex-0.162.0`: the codex-cli 0.162.0 musl build, strings of the binary;
 *   - `codex-recorded`: the ChatGPT-backend calls recorded in full at a stub
 *     on 0.159.1 and 0.144.1 (agent-sign-in.md §2.8 item 4) and reviewed under
 *     supported-agents.md §6.6;
 *   - `live-<date>`: seen in a live `mandu claude` run's net-proxy log.
 *
 * THE HOSTS. `api.anthropic.com` and `api.openai.com` (the API hosts, and
 * every host under them, as egress.ts `isModelHost`), `platform.claude.com`
 * (it answers the Messages API too: an unauthenticated `POST /v1/messages`
 * there returns the API's own `authentication_error`, probed 2026-10-18) and
 * `chatgpt.com` (the ChatGPT backend serves Codex's model turns,
 * `/backend-api/codex/responses`). `claude.ai` is not one: it shares
 * api.anthropic.com's address but answered the same probe with its web
 * challenge, and Claude Code calls nothing there directly (cc-2.1.302: every
 * `CLAUDE_AI_ORIGIN` use is a link shown to the user).
 *
 * Pure.
 */

/** The variable that turns the deny on (`1`); the launcher sets it whenever
 *  the confidentiality axis is on (services/net-proxy.ts). */
export const MODEL_HOST_DENY_ENV = "MANDU_NET_PROXY_MODEL_HOST_DENY";

/** One host's rule. */
export interface ModelHostRule {
  /** Lowercase, no trailing dot. */
  host: string;
  /** Hosts under it are model hosts too (egress.ts `isModelHost` matches the
   *  API hosts by suffix). */
  subdomains: boolean;
  /** The paths a program in the agent's tree may call here directly. */
  allow: readonly AllowedPath[];
}

/** One allowed path. `pattern` is matched segment by segment: `*` is exactly
 *  one segment, a final `**` any number (none included); every other
 *  segment is literal. The query is not part of the match. */
export interface AllowedPath {
  pattern: string;
  /** What the call is, and where it was read (see the header). */
  source: string;
}

const CC = "cc-2.1.302";
const CODEX = "codex-0.162.0";

/** Claude Code's Artifact pages service (`/api/frame/…` against
 *  BASE_API_URL, cc-2.1.302): the families the binary calls. The Artifact
 *  tools' local files are judged by the model proxy's upload gate
 *  (upload-gate.ts, kind `claude-artifact`). */
const FRAME_FAMILIES = [
  "blob", "comments", "content", "contract", "db", "deploy", "diag", "favorite", "frames", "perm", "read",
  "retitle", "subscribe", "sync", "track", "types", "unsubscribe", "upload", "user", "versions", "watch-token",
] as const;

/** The table. Hosts not listed are not model hosts here. */
export const MODEL_HOST_RULES: readonly ModelHostRule[] = [
  {
    host: "api.anthropic.com",
    subdomains: true,
    allow: [
      { pattern: "/api/hello", source: `${CC}: \`\${BASE_API_URL}/api/hello\`, the connectivity check` },
      { pattern: "/api/oauth/profile", source: `${CC}: \`\${BASE_API_URL}/api/oauth/profile\`, the signed-in account` },
      { pattern: "/api/oauth/validate", source: `${CC}: \`\${BASE_API_URL}/api/oauth/validate\`` },
      { pattern: "/api/oauth/usage", source: `${CC}: \`\${s.url}/api/oauth/usage\`, the plan's usage (/usage, the limit notices)` },
      { pattern: "/api/oauth/account/settings", source: `${CC}: \`/api/oauth/account/settings\`` },
      { pattern: "/api/oauth/account/grove_notice_viewed", source: `${CC}: \`/api/oauth/account/grove_notice_viewed\`` },
      { pattern: "/api/oauth/claude_cli/roles", source: `${CC}: ROLES_URL, the organization roles read at sign-in` },
      { pattern: "/api/oauth/claude_cli/create_api_key", source: `${CC}: API_KEY_URL, the Console sign-in's key` },
      { pattern: "/api/claude_cli_profile", source: `${CC}: \`\${BASE_API_URL}/api/claude_cli_profile\`` },
      { pattern: "/api/claude_cli/bootstrap", source: `${CC}: \`\${u}/api/claude_cli/bootstrap\` (skipped when nonessential traffic is off)` },
      { pattern: "/api/claude_code/settings", source: `${CC}: \`\${BASE_API_URL}/api/claude_code/settings\`, managed settings` },
      { pattern: "/api/claude_code/policy_limits", source: `${CC}: \`/api/claude_code/policy_limits\`, the organization's policy` },
      { pattern: "/api/claude_code/organizations/metrics_enabled", source: `${CC}: \`\${BASE_API_URL}/api/claude_code/organizations/metrics_enabled\`` },
      { pattern: "/api/claude_code_grove", source: `${CC}: \`/api/claude_code_grove\`, the data-use notice` },
      { pattern: "/api/claude_code_penguin_mode", source: `${CC}: \`\${BASE_API_URL}/api/claude_code_penguin_mode\`` },
      { pattern: "/api/organization/claude_code_first_token_date", source: `${CC}: \`/api/organization/claude_code_first_token_date\`` },
      { pattern: "/api/model_selector/*", source: `${CC}: \`/api/model_selector/\${o}\` (auth claude-ai-oauth), the model list` },
      { pattern: "/api/organizations/*/model_selector/*", source: `${CC}: \`/api/organizations/:orgUUID/model_selector/\${o}\`` },
      { pattern: "/api/eval/*", source: `${CC}: \`\${n}/api/eval/\${r}\`, the feature flags (GrowthBook)` },
      { pattern: "/api/eval-authed/*", source: `${CC}: \`\${n}/api/eval-authed/\${r}\`, the feature flags` },
      { pattern: "/api/features/*", source: `${CC}: \`\${n}/api/features/\${r}\`, the feature flags` },
      { pattern: "/api/web/domain_info", source: `${CC}: \`https://api.anthropic.com/api/web/domain_info?domain=…\`, WebFetch's check of a domain` },
      { pattern: "/v1/mcp_servers", source: `${CC}: \`\${BASE_API_URL}/v1/mcp_servers?limit=1000\`, the claude.ai connectors list` },
      { pattern: "/v1/design/mcp", source: `${CC}: DesignSync's \`POST /v1/design/mcp\` (gated per tool: upload-gate.ts)` },
      { pattern: "/api/artifacts/mcp", source: `${CC}: the Artifact tools' MCP server \`/api/artifacts/mcp\` (gated per tool: upload-gate.ts)` },
      { pattern: "/api/artifacts/mcp/upload/**", source: `${CC}: the Artifact tools' \`uploadPathPrefix\` (gated per tool: upload-gate.ts)` },
      ...FRAME_FAMILIES.flatMap((f) => [
        { pattern: `/api/frame/${f}`, source: `${CC}: the Artifact pages service, \`/api/frame/${f}…\` against BASE_API_URL` },
        { pattern: `/api/frame/${f}/**`, source: `${CC}: the Artifact pages service, \`/api/frame/${f}/…\`` },
      ]),
    ],
  },
  {
    host: "platform.claude.com",
    subdomains: false,
    allow: [
      { pattern: "/v1/oauth/token", source: `${CC}: TOKEN_URL, the sign-in's token exchange and refresh` },
      { pattern: "/docs/**", source: `${CC}: the documentation pages Claude Code links and fetches (\`https://platform.claude.com/docs/en/…\`)` },
      { pattern: "/llms.txt", source: `${CC}: \`https://platform.claude.com/llms.txt\`` },
    ],
  },
  {
    // codex-0.162.0: every api.openai.com URL is the provider's base
    // (`https://api.openai.com/v1`, routed to the openai-proxy by Mandu's
    // provider); `/auth` and `/profile` are token claim names, not calls.
    host: "api.openai.com",
    subdomains: true,
    allow: [],
  },
  {
    host: "chatgpt.com",
    subdomains: false,
    allow: [
      { pattern: "/backend-api/wham/usage", source: `codex-recorded; ${CODEX}: \`wham/usage\`, the plan's limits` },
      { pattern: "/backend-api/wham/accounts/check", source: `codex-recorded; ${CODEX}: \`wham/accounts/check\`` },
      { pattern: "/backend-api/wham/settings/user", source: `codex-recorded; ${CODEX}: \`wham/settings/user\`` },
      { pattern: "/backend-api/wham/config/bundle", source: `codex-recorded (supported-agents.md §6.6); ${CODEX}: \`wham/config/bundle\`` },
      { pattern: "/backend-api/ps/plugins/**", source: `codex-recorded; ${CODEX}: \`ps/plugins/{list,installed,suggested/codex,search,workspace/…}\`` },
      { pattern: "/backend-api/plugins/featured", source: `codex-recorded; ${CODEX}: \`plugins/featured\`` },
      { pattern: "/backend-api/plugins/export/curated", source: `codex-recorded (supported-agents.md §6.6); ${CODEX}: \`plugins/export/curated\`` },
    ],
  },
];

/** The hosts, for the identity and the launcher's parity test. */
export const MODEL_HOST_NAMES: readonly string[] = MODEL_HOST_RULES.map((r) => r.host);

/** `host` as compared: lowercase, no brackets, no port, no trailing dot. */
function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith("[")) return h.replace(/^\[|\](:\d+)?$/g, "");
  h = h.replace(/:\d+$/, "");
  return h.replace(/\.$/, "");
}

/** The rule `host` falls under, or null when it is no model host here. */
export function modelHostRule(host: string, rules: readonly ModelHostRule[] = MODEL_HOST_RULES): ModelHostRule | null {
  const h = normalizeHost(host);
  if (h === "") return null;
  for (const r of rules) {
    if (h === r.host || (r.subdomains && h.endsWith(`.${r.host}`))) return r;
  }
  return null;
}

/**
 * The path of a request target as the client sent it, before any
 * normalization: origin-form (`/a/b?q`) as is; absolute-form
 * (`https://host/a/b?q`) after its authority (`/` when it has none). null
 * for any other form (`*`, authority-form) and for a target holding a
 * fragment (`#`). The query is dropped. Pure.
 */
export function requestPath(target: string): string | null {
  // A fragment is never part of a request target (RFC 9112 §3.2); a server
  // that took `#` as a path character could resolve `/allowed#/../x` to
  // `/x`, so a target holding one is refused, never cut.
  if (target.includes("#")) return null;
  let rest: string;
  if (target.startsWith("/")) {
    rest = target;
  } else {
    const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/.exec(target);
    if (!m) return null;
    rest = target.slice(m[0].length);
    if (rest === "" || rest.startsWith("?") || rest.startsWith("#")) rest = `/${rest}`;
    if (!rest.startsWith("/")) return null;
  }
  const cut = rest.search(/[?#]/);
  return cut === -1 ? rest : rest.slice(0, cut);
}

/** The characters an allowed path may hold: RFC 3986 `pchar` and `/`, but
 *  no `%` (an encoded `/`, `.` or `\` could reach a different endpoint
 *  after the server decodes it), no `;` (path parameters), no `\`. */
const SAFE_PATH = /^\/[A-Za-z0-9._~!$&'()*+,=:@/-]*$/;

/** Why a path can never match, or null. A path the server might normalize
 *  to another one is refused whatever the list says. */
function unsafePath(path: string): string | null {
  if (!SAFE_PATH.test(path)) return "the path holds a character an allowed path never does (an escape, a `;` or a `\\`)";
  if (path.includes("//")) return "the path holds an empty segment";
  const segs = path.split("/").slice(1);
  if (segs.some((s) => s === "." || s === "..")) return "the path holds a dot segment";
  return null;
}

/** Does `path` (safe, no query) match `pattern`? A trailing `/` on the path
 *  is ignored. */
export function pathMatches(pattern: string, path: string): boolean {
  const p = pattern.split("/").slice(1);
  let s = path.split("/").slice(1);
  if (s.length > 1 && s[s.length - 1] === "") s = s.slice(0, -1);
  for (let i = 0; i < p.length; i++) {
    const seg = p[i]!;
    if (seg === "**" && i === p.length - 1) return true;
    if (i >= s.length) return false;
    if (seg === "*") {
      if (s[i] === "") return false;
      continue;
    }
    if (seg !== s[i]) return false;
  }
  return s.length === p.length;
}

export type ModelPathDecision =
  | { allowed: true; host: string; pattern: string; path: string }
  | { allowed: false; host: string; reason: string };

/**
 * The decision for one request to a model host: allowed only when its path
 * is on the host's list. `target` is the request target as the client sent
 * it (requestPath). The reason names the host and the path, never the query,
 * the headers or the body. Pure.
 */
export function modelPathDecision(rule: ModelHostRule, method: string, target: string): ModelPathDecision {
  const path = requestPath(target);
  const refuse = (why: string, shown: string): ModelPathDecision => ({
    allowed: false,
    host: rule.host,
    reason:
      `${method} ${shown} on model host ${rule.host} is refused: ${why}. A program the agent runs reaches a model only ` +
      "through Mandu's model proxy, so it may call a model host directly only for the account and sign-in calls Mandu " +
      "lists (fail-closed)",
  });
  if (path === null) return refuse("the request target is not a path", "(no path)");
  const shown = path.length > 120 ? `${path.slice(0, 120)}…` : path;
  const unsafe = unsafePath(path);
  if (unsafe) return refuse(unsafe, JSON.stringify(shown));
  for (const a of rule.allow) {
    if (pathMatches(a.pattern, path)) return { allowed: true, host: rule.host, pattern: a.pattern, path: shown };
  }
  return refuse("the path is not on the list of calls an agent makes there directly", shown);
}

/** The refusal of a CONNECT to a model host whose requests this proxy cannot
 *  read (TLS inspection off): the whole host, since no path can be judged. */
export function modelHostTunnelReason(host: string): string {
  return (
    `model host ${host} is refused: TLS inspection is off, so the request's path cannot be read, and a program the ` +
    "agent runs reaches a model only through Mandu's model proxy (fail-closed)"
  );
}
