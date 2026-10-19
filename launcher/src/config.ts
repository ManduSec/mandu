/**
 * config — `~/.mandu/config.toml` support (packaging.md §7): per-user
 * defaults replacing the MANDU_* env spread. Precedence: flags > env > config
 * > defaults, achieved cheaply — config values are applied to `env` ONLY where
 * env has not already set them, then parse.ts's existing env→default precedence
 * takes over and flags override env. Env vars stay the e2e harness surface.
 *
 * The file uses friendly keys mapped to the MANDU_* vars; a tiny TOML subset
 * (key = value, [sections] flattened, # comments, strings/bools/ints) is enough
 * and keeps the package free of a TOML runtime dependency.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { readFileSync } from "node:fs";
import { manduPath } from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;
type TomlValue = string | number | boolean;

/** Friendly config key → the MANDU_* env var it seeds, with value coercion. */
const CONFIG_TO_ENV: Record<string, { env: string; kind: "bool" | "num" | "str" }> = {
  "reply-filter": { env: "MANDU_REPLY_FILTER", kind: "bool" },
  // Protection mode (protection-modes.md): one name over the two axis keys
  // below. An axis key in the same file beats the mode for that axis only.
  "mode": { env: "MANDU_MODE", kind: "str" },
  "confidentiality": { env: "MANDU_CONFIDENTIALITY", kind: "bool" },
  "require-confinement": { env: "MANDU_REQUIRE_CONFINEMENT", kind: "bool" },
  "env-secrets": { env: "MANDU_ENV_SECRETS", kind: "bool" },
  // Another agent's login file in a session that does not run that agent
  // (secret-discovery.md §1.10): "twin" (the default, a placeholder copy) or
  // "raw" (registered but readable). agent-login.ts otherAgentLoginsRaw.
  "other-agent-logins": { env: "MANDU_OTHER_AGENT_LOGINS", kind: "str" },
  "secrets-ask": { env: "MANDU_SECRETS_ASK", kind: "str" },
  "secret-bind": { env: "MANDU_SECRET_BIND", kind: "bool" },
  "secrets-ask-timeout": { env: "MANDU_SECRETS_ASK_TIMEOUT", kind: "num" },
  "integrity": { env: "MANDU_INTEGRITY", kind: "bool" },
  "fs-sync": { env: "MANDU_FS_SYNC", kind: "bool" },
  "fs-sync-eager": { env: "MANDU_FS_SYNC_EAGER", kind: "bool" },
  // Retired rung (2026-07-14) — mapping kept so a stale config's
  // `fs-preload = false` stays harmless; `= true` fails closed in parse.ts.
  "fs-preload": { env: "MANDU_FS_PRELOAD", kind: "bool" },
  "net-proxy": { env: "MANDU_NET_PROXY", kind: "bool" },
  "net-proxy-mitm": { env: "MANDU_NET_PROXY_MITM", kind: "bool" },
  // The held request (egress-hold.ts): ms a request waiting on an Approvals
  // card waits for the answer; unset = 60 s in an interactive session, else 0.
  "egress-hold-ms": { env: "MANDU_EGRESS_HOLD_MS", kind: "num" },
  "exec-wrap": { env: "MANDU_EXEC_WRAP", kind: "bool" },
  "exec-box": { env: "MANDU_EXEC_BOX", kind: "bool" },
  "exec-clean-box": { env: "MANDU_EXEC_CLEAN_BOX", kind: "bool" },
  "landlock-net": { env: "MANDU_LANDLOCK_NET", kind: "bool" },
  "landlock-net-strict": { env: "MANDU_LANDLOCK_NET_STRICT", kind: "bool" },
  "landlock-net-bind": { env: "MANDU_LANDLOCK_NET_BIND", kind: "str" },
  "net-guard": { env: "MANDU_NET_GUARD", kind: "bool" },
  "codex-shell-network": { env: "MANDU_CODEX_SHELL_NETWORK", kind: "bool" },
  "net-allow": { env: "MANDU_NET_ALLOW", kind: "str" },
  "net-guard-git": { env: "MANDU_NET_GUARD_GIT", kind: "bool" },
  "no-kernel": { env: "MANDU_NO_KERNEL", kind: "bool" },
  "proxy-port": { env: "MANDU_PROXY_PORT", kind: "num" },
  "net-proxy-port": { env: "MANDU_NET_PROXY_PORT", kind: "num" },
  "openai-proxy-port": { env: "MANDU_OPENAI_PROXY_PORT", kind: "num" },
  "dashboard-port": { env: "DASHBOARD_PORT", kind: "num" },
  "arbiter-sock": { env: "MANDU_ARBITER_SOCK", kind: "str" },
  "ullm-model": { env: "MANDU_ULLM_MODEL", kind: "str" },
  // The data-law document (policy-surface.md §2.1): origin lists,
  // per-tool overrides, per-command exec entries. Read by the ARBITER at boot
  // (MANDU_POLICY_FILE); default <home>/policy.yaml when unset.
  "policy-file": { env: "MANDU_POLICY_FILE", kind: "str" },
  // The daily check for a newer Mandu release (update-check.ts,
  // packaging.md §11.5); `false` turns it off.
  "update-check": { env: "MANDU_UPDATE_CHECK", kind: "bool" },
  // The launch line for a preview agent (Goose, OpenCode 1 and 2;
  // agent-versions.ts launchPreviewNotice); `false` hides it.
  "preview-notice": { env: "MANDU_PREVIEW_NOTICE", kind: "bool" },
};

/** The template `mandu init` writes. Everything commented → an empty config
 *  behaves exactly like no config (all defaults), so init is always safe. */
export const DEFAULT_CONFIG_TOML = `# Mandu config — per-user defaults for \`mandu <agent>\`.
# Precedence: command-line flags > MANDU_* env vars > this file > built-in defaults.
# Uncomment and edit any line to change a default. Booleans are true/false.

# ── protection mode: what Mandu enforces (\`mandu mode\` shows and sets it) ──
#   secrets    your keys and credentials cannot leave
#   off        observe only, enforce nothing
#   (injection and full are frozen: they need MANDU_EXPERIMENTAL_INTEGRITY=1,
#   docs/design/architecture/protection-modes.md §10)
# Read once when the protection service starts; \`mandu stop\`, then relaunch, to apply.
# mode = "secrets"

# ── user-reply egress filter (desymbolize the agent's stdout for you) ──
# reply-filter = true

# ── secrets: refuse instead of degrading when this host cannot confine them ──
# Default false: on a host without unprivileged user namespaces (Ubuntu 24.04
# before \`mandu setup\`) the launch proceeds in the weaker \`gated\` posture
# with a loud notice. Recommended true for managed deployments.
# require-confinement = false

# ── secrets in the environment: masked before the agent inherits them ──
# Variables whose NAME says secret (*_TOKEN, *_SECRET, *PASSWORD, *_PWD, *_PAT,
# *_API_KEY, *_WEBHOOK, *_WEBHOOK_URL, …; a *_PWD holding a directory, such as
# HOST_PWD, stays), any value that is a URL with a password and any value
# holding a key in a known format (a GitHub, GitLab, Stripe, Slack, AWS, …
# key, a private key, in JSON too) reach the agent as symbols; the real value
# is put back on the way to a host it is bound to. The agents' own sign-in
# variables (ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_CUSTOM_HEADERS,
# which can carry an Authorization header, CLAUDE_CODE_OAUTH_TOKEN,
# OPENAI_API_KEY, CODEX_API_KEY; under \`mandu goose\`, the routed provider's
# key, such as OPENROUTER_API_KEY) are never masked, in any launch.
# env-secrets = true

# ── another AI agent's login files: a placeholder copy unless that agent runs ──
# The login of the agent you launch stays readable to it. Another agent's
# (\`~/.codex/auth.json\` under \`mandu claude\`, \`~/.claude.json\` under
# \`mandu codex\`) is masked like any credential file, so that agent started
# inside the session cannot log in. "raw" leaves those files readable, and
# usable with that agent's own services, for that agent started inside (their
# values are still masked in what reaches the AI).
# other-agent-logins = "twin"

# ── TLS inspection at the egress proxy: on whenever secrets are protected ──
# A masked value is put back only inside a request the proxy can read, so in
# \`secrets\` / \`full\` mode the proxy terminates TLS with a per-session CA that
# the agent's tools are told to trust (curl, node, python, git). A program
# that pins its certificate cannot use it; set false to keep the blind tunnel.
# net-proxy-mitm = true

# ── a request waiting on an Approvals card: held for your answer ──
# In an interactive session (a terminal, not \`claude -p\` / \`codex exec\`, not
# CI) a request stopped only by a card you have not answered yet waits up to
# a minute for the answer, which then decides that request; elsewhere it is
# stopped at once. A value here applies to every session (milliseconds, at
# most 300000); 0 never holds.
# egress-hold-ms = 0

# ── filesystem chokepoint (dual-view git worktree; auto-on for git repos) ──
# fs-sync = true
# fs-sync-eager = true          # sync AgentView→HumanView at each tool call

# ── network + exec chokepoints (ON by default, degrade when unavailable) ──
# net-proxy = true              # cooperative egress gate (HTTP(S)_PROXY)
# exec-wrap = true              # PATH-shadow curl/wget/nc through the arbiter
# exec-box = true               # box read-only commands in the AgentShell (bwrap)
# exec-clean-box = false        # the CLEAN box first (on by default where the session's guard runs it; false turns it off)
# landlock-net = true           # whole-agent TCP CONNECT allow-list (kernel ≥ 6.7)
# landlock-net-strict = false   # also deny the workflow ports 443 + 22
# landlock-net-bind = "4096"     # ports the agent may LISTEN on (a local TUI server / gateway)
# net-guard = true              # IP/domain-aware connect(2) guard (kernel ≥ 5.6)
# codex-shell-network = true    # mandu codex: turn on the network of Codex's own command
#                               #   sandbox (said at launch; the guard decides where commands
#                               #   connect; a network setting in your Codex config wins)
# net-allow = "10.0.0.0/8:*,registry.npmjs.org:443"   # curate :443 (drops the *:443 fallback)
# net-guard-git = true          # auto-allow workspace git-remote hosts when narrowed (strict/curated)

# ── portable posture: drop ALL kernel-tier rungs in one switch (--no-kernel) ──
# Keeps the full userspace defense (context proxy + fs-sync + net-proxy +
# exec-wrap + reply-filter); turns off exec-box + landlock-net + the namespace
# stubs. For hosts without bwrap/userns/Landlock, or to force the portable posture.
# no-kernel = false

# ── ports / paths ──
# Unset = a free port the kernel picks for each launch (the default), so a
# second user or another Mandu stack on this machine never collides with
# you. Pin one only if something outside Mandu must find it.
# proxy-port = 0               # the model-API proxy (claude)
# openai-proxy-port = 0        # the model-API proxy (codex)
# net-proxy-port = 0           # the egress gate
# dashboard-port = 0           # \`mandu dashboard\` reuses your running dashboard,
#                              #   else starts one on a free port
# arbiter-sock = "/run/user/1000/mandu/arbiter.sock"
# policy-file = "~/.mandu/policy.yaml"   # the data law: trusted origins, per-tool
#                                                 # overrides, exec entries (read by the arbiter;
#                                                 # an INVALID file refuses to start, a missing
#                                                 # one means the built-ins are the whole law)

# ── quarantined U-LLM model (inspect_symbol) ──
# ullm-model = "claude-haiku-4-5"

# ── update notice: once a day a launch asks GitHub for the release list ──
# (one HTTPS GET to api.github.com, nothing about you or the session sent)
# and says in one line when a newer Mandu is out. false turns it off.
# update-check = true

# ── preview notice: Goose and OpenCode (1 and 2) are previews (tested less
# than Claude Code and Codex); each of their launches says so in one line.
# false hides that line.
# preview-notice = true
`;

/** Resolve the config path: `<home>/config.toml`, the path table's
 *  `config-toml` (on-disk-layout.md §5), where the home is $MANDU_HOME, else
 *  ~/.mandu. null when neither MANDU_HOME nor HOME is set. */
export function configPath(env: Env): string | null {
  if (!env["MANDU_HOME"] && !env["HOME"]) return null;
  return manduPath("config-toml", env, env["HOME"] ?? "");
}

/** Parse the supported TOML subset into a flat map. Lenient: unparseable lines
 *  are skipped, section headers are ignored (keys are a flat namespace), and
 *  a key the launcher does not know is ignored by loadConfigEnv. */
export function parseToml(text: string): Record<string, TomlValue> {
  const out: Record<string, TomlValue> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("[")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let rest = line.slice(eq + 1).trim();
    if (!key) continue;
    const q = rest[0];
    if (q === '"' || q === "'") {
      const end = rest.indexOf(q, 1);
      if (end > 0) out[key] = rest.slice(1, end);
      continue;
    }
    const ci = rest.indexOf(" #"); // strip an inline comment
    if (ci >= 0) rest = rest.slice(0, ci).trim();
    if (rest === "true") out[key] = true;
    else if (rest === "false") out[key] = false;
    else if (/^-?\d+$/.test(rest)) out[key] = parseInt(rest, 10);
    else if (/^-?\d*\.\d+$/.test(rest)) out[key] = parseFloat(rest);
    else out[key] = rest;
  }
  return out;
}

function coerce(v: TomlValue, kind: "bool" | "num" | "str"): string {
  if (kind === "bool") return v === true || v === "true" ? "1" : "0";
  return String(v);
}

/** Read + map config to an env-shaped record. Empty on absent/unreadable file. */
export function loadConfigEnv(env: Env, read: (p: string) => string | null = safeRead): Record<string, string> {
  const path = configPath(env);
  if (!path) return {};
  const text = read(path);
  if (text === null) return {};
  const cfg = parseToml(text);
  const out: Record<string, string> = {};
  for (const [key, spec] of Object.entries(CONFIG_TO_ENV)) {
    if (!(key in cfg)) continue;
    out[spec.env] = coerce(cfg[key]!, spec.kind);
  }
  return out;
}

/**
 * Apply config values to `env` as low-priority defaults: set each config-derived
 * MANDU_* var ONLY where env has not already set it (env wins over config).
 * Mutates `env` in place — in the real CLI that is process.env, so services and
 * the agent inherit the defaults too. A no-op when no config file exists.
 */
export function applyConfigDefaults(env: Env, read: (p: string) => string | null = safeRead): void {
  const configEnv = loadConfigEnv(env, read);
  // An exported MANDU_MODE speaks for BOTH axes at the env level, so the
  // file's axis keys (a lower level) must not leak in beside it and override
  // it (mode.ts: levels resolve per axis, highest level first).
  const envNamesMode = (env["MANDU_MODE"] ?? "") !== "";
  for (const [k, v] of Object.entries(configEnv)) {
    if (envNamesMode && (k === "MANDU_INTEGRITY" || k === "MANDU_CONFIDENTIALITY")) continue;
    if (env[k] === undefined) env[k] = v;
  }
}

/** Read an optional file: absent (ENOENT, or ENOTDIR when a parent is not a
 *  directory, as under a `/dev/null/...` test home) or unreadable → null. */
function safeRead(p: string): string | null {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}
