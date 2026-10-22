/**
 * agent-login — is the wrapped agent logged in? (open-source release
 * checklist a8; packaging.md §7 "the agent's login").
 *
 * A fresh user with no login saw only the agent's own "Not logged in", and
 * `mandu doctor` never mentioned it. This module answers the question for
 * `mandu doctor` (a row per agent) and for the launch (one plain line before
 * the agent starts; a WARNING, never a refusal: detection can be wrong). The
 * one refusal is codexKeyRefusal: a `mandu codex` model session with no way
 * to authenticate at all, which Codex itself could not run
 * (agent-sign-in.md §2.3, §2.6).
 *
 * EXISTENCE CHECKS ONLY. It asks whether a login variable is set and whether
 * a credential file exists; it never opens, reads or prints a credential.
 * It never logs anyone in: a Claude subscription login is first-party only
 * (agent-sign-in.md §1), so the fix it names is always the agent's own login
 * command.
 *
 * GOOSE (supported-agents.md §5.6.1). `goose configure` saves the key in the
 * system keyring (the Secret Service, over the D-Bus session bus) or, when
 * the keyring is off or unavailable, in its own `secrets.yaml`. Under a
 * guarded launch the agent cannot reach the session bus (unix-policy.ts: it
 * runs programs outside the confinement), so a keyring-only login cannot
 * work there: `gooseKeyringNote` says so in one line with the two fixes.
 * The keyring check (`keyringItem`, doctor only) asks the Secret Service
 * whether an item EXISTS (SearchItems answers object paths, never a
 * secret); `realGooseKeyringItem` is that call. On macOS Goose keeps its
 * key in the login Keychain instead, which the Seatbelt profile leaves
 * reachable: there the question is `security find-generic-password` WITHOUT
 * `-w` / `-g` (the item's attributes, never its password).
 *
 * A SUBAGENT provider (GOOSE_SUBAGENT_PROVIDER, pinned by the launch to a
 * routed provider, goose-route.ts gooseRoutePlan) other than the session's
 * reads its own key variable: the same three places are checked for it, and
 * both launch lines and the doctor say when only the subagents lack a login.
 *
 * Pure given its deps (env + fileExists + platform), unit-tested without a
 * real HOME. PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { codexTalksToModel } from "./codex-argv.js";
import { readGooseArgv } from "./goose-argv.js";
import { gooseCompatSpec, gooseConfigDir, gooseConfigScalars, gooseRoutePlan, type GooseRoutedProvider } from "./goose-route.js";

type Env = Record<string, string | undefined>;

/** The agents whose login this module knows how to find. openclaw and
 *  opencode keep provider credentials in their own config (merged under the
 *  routing override, agent-e2e-harness.md §9) and are not probed. */
export type LoginAgent = "claude" | "codex" | "goose";

export interface LoginProbeDeps {
  env: Env;
  /** The home directory to resolve `~` against (env.HOME, else the OS home). */
  home: string;
  fileExists: (path: string) => boolean;
  platform: "linux" | "darwin" | "win32";
  /** Goose: the text of its `config.yaml` (for GOOSE_DISABLE_KEYRING), or
   *  null when absent. Not a credential file. Absent dep: not read. */
  readGooseConfig?: (path: string) => string | null;
  /** Goose: does the system keyring hold an item with these attributes
   *  (Linux: the Secret Service; macOS: the login Keychain)? true / false,
   *  or null when it cannot be asked (no session bus, no dbus-send, no
   *  `security`). EXISTENCE only (`realGooseKeyringItem`). Absent dep: not
   *  asked (the launch never asks; `mandu doctor` does). */
  keyringItem?: (attrs: Readonly<Record<string, string>>) => boolean | null;
  /** Goose: the launch's argv, whose `--provider` picks the key variable
   *  (`gooseKeyVar`). Absent (doctor): `goose session`. */
  gooseArgv?: readonly string[];
}

export interface LoginStatus {
  agent: LoginAgent;
  /** found: a login source exists. missing: none of the known sources does.
   *  unknown: the login lives where an existence check cannot see it (Claude
   *  Code on macOS keeps it in the Keychain). */
  state: "found" | "missing" | "unknown";
  /** WHERE the login was found (a variable NAME or a file PATH, never a value). */
  via?: string;
  /** Codex only: the login is Codex's own `codex login` (auth.json), which
   *  `mandu codex` relays through its model proxy (agent-sign-in.md §2
   *  §4), not a key variable. */
  signIn?: boolean;
  /** Goose only: the login is (found) or may be (unknown) in the system
   *  keyring, which a guarded `mandu goose` launch cannot reach on Linux.
   *  Not set for a login found in the macOS Keychain (reachable there). */
  keyring?: boolean;
  /** Goose only: the subagents' own login, when the launch pins
   *  GOOSE_SUBAGENT_PROVIDER to a provider other than the session's (its
   *  key variable differs). Absent: the subagents use the session's. */
  subagent?: GooseSubagentLogin;
  /** How to log in, in plain words (shown when state is missing). */
  howTo: string;
}

/** The subagents' login (LoginStatus.subagent): the same places as the
 *  session's, for the subagent provider's key variable. */
export interface GooseSubagentLogin {
  provider: GooseRoutedProvider;
  /** null: a provider that takes no key (ollama) */
  keyVar: GooseKeyVar | null;
  state: "found" | "missing" | "unknown";
  via?: string;
  keyring?: boolean;
  howTo: string;
}

const nonEmpty = (v: string | undefined): boolean => v !== undefined && v.trim() !== "";

/** Claude Code's login sources, in the order Claude Code itself prefers them:
 *  an API key / auth token / OAuth token variable, a third-party provider
 *  switch (Bedrock / Vertex / Foundry carry their own cloud credentials), then
 *  the subscription login file under its config dir. */
const CLAUDE_ENV = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"] as const;
const CLAUDE_PROVIDER_SWITCHES = ["CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"] as const;
/** Under `mandu codex`, Codex reaches the model through the launcher's own
 *  provider (env-compose.ts codexProviderToml). With one of these variables
 *  set the provider reads its key from it (`env_key`); with none, the
 *  provider uses Codex's own `codex login` (`requires_openai_auth`: a ChatGPT
 *  sign-in or a saved key), which the model proxy relays
 *  (agent-sign-in.md §2.4). A user base URL (MANDU_OPENAI_BASE_URL) keeps
 *  `env_key`: that server wants its own key. */
const CODEX_ENV = ["OPENAI_API_KEY", "CODEX_API_KEY"] as const;

export const CLAUDE_LOGIN_HOWTO =
  "run `claude` once without mandu and log in (or `claude /login`), or set ANTHROPIC_API_KEY";
/** Either works under `mandu codex` (see CODEX_ENV). Plain Codex 0.154
 *  honors CODEX_API_KEY but answers 401 to a bare OPENAI_API_KEY without
 *  `codex login` (os-test-matrix.md §10.14.1), so CODEX_API_KEY is named
 *  first. */
export const CODEX_LOGIN_HOWTO =
  "run `codex login` once without mandu (a ChatGPT plan), or set CODEX_API_KEY (or OPENAI_API_KEY) to an OpenAI API key";

/** Goose (1.53.0, crates/goose/src/config/base.rs `get_secret`): the
 *  routed provider's key variable (ANTHROPIC_API_KEY, OPENAI_API_KEY for
 *  the openai provider, a Chat Completions provider's own, goose-route.ts
 *  GOOSE_COMPAT_PROVIDERS), else its secret store: the system keyring
 *  (service `goose`, account `secrets`, one JSON object of every secret),
 *  falling back to `<config dir>/secrets.yaml` when the keyring has no item
 *  or cannot be reached; with GOOSE_DISABLE_KEYRING set (env, any value; or
 *  `true` / `"1"` in config.yaml) only the file. The fix names the key
 *  variable of the provider the launch routes. */
export function gooseLoginHowTo(keyVar: GooseKeyVar = "ANTHROPIC_API_KEY"): string {
  return `set ${keyVar}, or run \`GOOSE_DISABLE_KEYRING=1 goose configure\` once without mandu to save the key in Goose's secrets.yaml`;
}
export const GOOSE_LOGIN_HOWTO = gooseLoginHowTo();
export type GooseKeyVar = "ANTHROPIC_API_KEY" | "OPENAI_API_KEY" | "LITELLM_API_KEY" | "OPENROUTER_API_KEY" | "XAI_API_KEY" | "TETRATE_API_KEY";

/** The key variable of the provider this Goose launch routes (goose-route.ts
 *  `gooseRoutePlan`: `--provider`, then GOOSE_PROVIDER, then config.yaml;
 *  anthropic by default and for a refused launch); null for a provider that
 *  takes no key (ollama). Pure but for the config read. */
export function gooseKeyVar(argv: readonly string[] | undefined, env: Env, readConfig?: (path: string) => string | null): GooseKeyVar | null {
  return gooseKeyVars(argv, env, readConfig).main;
}

/** A routed provider's key variable: its own for a Chat Completions
 *  provider (goose-route.ts GOOSE_COMPAT_PROVIDERS), null for one that
 *  takes none (ollama). */
const keyVarOf = (p: GooseRoutedProvider): GooseKeyVar | null =>
  p === "anthropic" ? "ANTHROPIC_API_KEY" : p === "openai" ? "OPENAI_API_KEY" : ((gooseCompatSpec(p)?.keyVar ?? null) as GooseKeyVar | null);

/** The key variables of the session's provider and of the subagents'
 *  (GOOSE_SUBAGENT_PROVIDER as the launch pins it: env, then config.yaml,
 *  else the session's), from the same `gooseRoutePlan` the launch routes
 *  by. Pure but for the config read. */
export function gooseKeyVars(
  argv: readonly string[] | undefined,
  env: Env,
  readConfig?: (path: string) => string | null,
): { main: GooseKeyVar | null; sub: GooseKeyVar | null; subProvider: GooseRoutedProvider } {
  const path = join(gooseConfigDir(env), "config.yaml");
  const text = readConfig?.(path) ?? null;
  const cfg = { path, values: text === null ? null : gooseConfigScalars(text), customProviders: [] };
  const { routing } = gooseRoutePlan(argv ?? ["goose", "session"], env, cfg);
  return { main: keyVarOf(routing.provider), sub: keyVarOf(routing.subagentProvider), subProvider: routing.subagentProvider };
}
/** The Secret Service attributes Goose's keyring item carries (keyring crate
 *  v3: `service`, `username`). */
export const GOOSE_KEYRING_ATTRS: Readonly<Record<string, string>> = { service: "goose", username: "secrets" };
/** Where a Goose login found in the macOS Keychain is said to be (`via`). */
export const GOOSE_KEYCHAIN_VIA = "the macOS Keychain";

/** Goose's secrets file for this env (goose-route.ts gooseConfigDir). Pure. */
export function gooseSecretsFile(env: Env): string {
  return join(gooseConfigDir(env), "secrets.yaml");
}

/** The credential files THIS launch's agent reads its own key from, which
 *  the secret setup registers but leaves readable (secret-setup.ts
 *  `agentOwnFiles`): Goose's secrets.yaml under `mandu goose` (a wrapper
 *  under `--target goose` included). Claude Code's, Codex's and OpenCode's
 *  logins are keyed by the arbiter's discovery instead (secret-discovery.ts
 *  AGENT_LOGIN_FILES, from `launchLoginKeying`): left out of the walk, so
 *  unregistered, in the launch that runs on them. A Goose file is a catalog
 *  secret like any other under every other agent. Pure. */
export function agentOwnCredentialFiles(target: string, env: Env): string[] {
  return target === "goose" ? [gooseSecretsFile(env)] : [];
}

/** The agents whose login files the arbiter's discovery keys per launch
 *  (secret-discovery.ts AGENT_LOGIN_FILES), by the names a user reads. */
export const AGENT_LOGIN_NAMES: Readonly<Record<string, string>> = { claude: "Claude Code", codex: "Codex", opencode: "OpenCode" };

/** Every `--target`, by the name a user reads (`mandu why`, `mandu doctor
 *  --secrets --target`): one spelling for both. */
export const AGENT_DISPLAY_NAMES: Readonly<Record<string, string>> = {
  ...AGENT_LOGIN_NAMES, goose: "Goose", openclaw: "OpenClaw", shell: "a plain command",
};

/** `agent`'s name as a user reads it (AGENT_DISPLAY_NAMES), else as given. */
export function agentDisplayName(agent: string): string {
  return AGENT_DISPLAY_NAMES[agent] ?? agent;
}

/**
 * The sessions that leave `agent`'s login raw, in words: the rule of the
 * arbiter's `keptLoginOwners` with `launchLoginKeying`'s AI-helper term
 * (secret-discovery.md §1.10). ONE wording for `mandu why`, `mandu doctor
 * --secrets` and the docs. Pure.
 */
export function loginKeptWhere(agent: string): string {
  switch (agent) {
    case "claude":
      return "mandu claude, a plain command (mandu -- <command>) and mandu openclaw, and mandu goose or mandu opencode while " +
        "Mandu's AI helper runs claude (neither ANTHROPIC_API_KEY nor MANDU_ULLM_API_KEY set, and no --no-mcp)";
    case "codex": return "mandu codex and mandu openclaw";
    default: return `mandu ${agent}`;
  }
}

/**
 * What a launch tells the secret walk about the agents it runs
 * (secret-discovery.md §1.10): the launched agent (`target`), and the CLI
 * the AI helper runs in the agent's world when it runs one (`ullmBinary`:
 * inspect-mcp's `claude -p` or `codex exec` in CLI mode, parse.ts; none in
 * API mode or under `--no-mcp`). The walk leaves those agents' login files
 * raw and discovers every other agent's (`keptLoginOwners` in the arbiter).
 * Pure.
 */
export function launchLoginKeying(plan: { target: string; writeMcp?: boolean; ullm?: { mode: "api" | "cli"; binary?: string } }): { target: string; ullmBinary?: string } {
  const binary = plan.writeMcp !== false && plan.ullm?.mode === "cli" ? plan.ullm.binary ?? "claude" : undefined;
  return { target: plan.target, ...(binary !== undefined ? { ullmBinary: binary } : {}) };
}

/**
 * The variables that move an agent's login file (CLAUDE_CONFIG_DIR,
 * CODEX_HOME, XDG_DATA_HOME). MIRROR of the arbiter's LOGIN_ENV
 * (arbiter/policy/secret-discovery.ts `agentLoginPaths`); the launcher never
 * imports the arbiter, so tests/stack/login-env-parity.test.ts pins the two
 * lists equal. Sent so the walk, the registration and the session's
 * net-proxy know where THIS session's agents log in; only these names,
 * which hold paths.
 */
export const LOGIN_ENV: readonly string[] = ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_DATA_HOME"];

/** The LOGIN_ENV values in `env` that are absolute paths. Pure. */
export function loginEnvOf(env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of LOGIN_ENV) {
    const v = env[name];
    if (typeof v === "string" && v.startsWith("/")) out[name] = v;
  }
  return out;
}

/** What a session tells its net-proxy about the login files it leaves raw
 *  (arbiter secret-discovery.ts `SessionLogins`, secret-discovery.md §1.10). */
export interface SessionLogins {
  home: string;
  target: string;
  ullmBinary?: string;
  otherLoginsRaw?: boolean;
  loginEnv?: Record<string, string>;
  /** The project MCP configs the session's agent reads in its own process
   *  (secret-discovery.md §2.10): Claude Code's `.mcp.json` in the
   *  directories it runs in, OpenCode's `opencode.json(c)` there and up to
   *  the repository's top, those that exist at the launch. */
  mcpConfigs?: string[];
}

/** The agents whose project `.mcp.json` the session's agent reads: Claude
 *  Code under every target whose login the walk keeps for it (its own, a
 *  plain command's, OpenClaw's). Mirrors the arbiter's `keptLoginOwners`
 *  for `claude`; the arbiter keeps a path only when a kept agent reads it. */
const CLAUDE_MCP_TARGETS: ReadonlySet<string> = new Set(["claude", "shell", "openclaw"]);

/** A repository's metadata entry: where OpenCode stops looking up. */
const REPO_META = ".git";

/** How many directories up `sessionMcpConfigs` looks for OpenCode's. */
const MAX_OPENCODE_UP = 32;

/**
 * The project MCP configs the session's agent reads in its own process
 * (secret-discovery.md §2.10): `<dir>/.mcp.json` for the human's and the
 * agent's directories when the target runs Claude Code; under `mandu
 * opencode` (2026-10-22) `opencode.json` and `opencode.jsonc` in those
 * directories and each one above, up to the first that holds a
 * repository (OpenCode's own lookup, which stops at its worktree's top);
 * those that exist (`exists`). Pure but for `exists`.
 */
export function sessionMcpConfigs(
  plan: { target: string; cwd?: string; humanCwd?: string },
  exists: (p: string) => boolean = existsSync,
): string[] {
  const dirs = [...new Set([plan.humanCwd, plan.cwd].filter((d): d is string => typeof d === "string" && d.startsWith("/")))];
  if (CLAUDE_MCP_TARGETS.has(plan.target)) return dirs.map((d) => join(d, ".mcp.json")).filter((p) => exists(p));
  if (plan.target !== "opencode") return [];
  const out = new Set<string>();
  for (const start of dirs) {
    let d = start;
    for (let n = 0; n < MAX_OPENCODE_UP; n++) {
      for (const f of ["opencode.json", "opencode.jsonc"]) if (exists(join(d, f))) out.add(join(d, f));
      if (exists(join(d, REPO_META))) break;
      const up = dirname(d);
      if (up === d) break;
      d = up;
    }
  }
  return [...out];
}

/**
 * The login files THIS session leaves raw, as its net-proxy hands them to the
 * egress tripwire (secret-discovery.md §1.10 "In the session that runs the
 * agent"): the walk's keying (`launchLoginKeying`: the launched agent and the
 * AI helper's CLI), every agent's under MANDU_OTHER_AGENT_LOGINS=raw, and
 * where they live (HOME, LOGIN_ENV). Another session's launch may have
 * registered those files (registration is global and durable); in this
 * session their rows must not refuse the agent's own traffic (a ChatGPT
 * bearer to chatgpt.com, an OAuth refresh, an MCP server's token). The
 * arbiter turns this into login-file paths only. Pure.
 */
export function sessionLogins(
  plan: { target: string; writeMcp?: boolean; ullm?: { mode: "api" | "cli"; binary?: string }; cwd?: string; humanCwd?: string },
  env: Env,
  home: string,
  exists: (p: string) => boolean = existsSync,
): SessionLogins {
  const k = launchLoginKeying(plan);
  const loginEnv = loginEnvOf(env);
  const mcpConfigs = sessionMcpConfigs(plan, exists);
  return {
    home, target: k.target,
    ...(k.ullmBinary !== undefined ? { ullmBinary: k.ullmBinary } : {}),
    ...(otherAgentLoginsRaw(env) ? { otherLoginsRaw: true } : {}),
    ...(Object.keys(loginEnv).length > 0 ? { loginEnv } : {}),
    ...(mcpConfigs.length > 0 ? { mcpConfigs } : {}),
  };
}

/** One spelling of a SessionLogins-shaped value, to compare a running
 *  net-proxy's published one (`/_mandu/identity`) with a launch's: the known
 *  fields in a fixed order, "" for a value that is not one (a proxy that
 *  predates the field). Pure. */
export function sessionLoginsKey(v: unknown): string {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return "";
  const o = v as Record<string, unknown>;
  if (typeof o["home"] !== "string") return "";
  const envIn = o["loginEnv"] !== null && typeof o["loginEnv"] === "object" ? o["loginEnv"] as Record<string, unknown> : {};
  const env = Object.keys(envIn).filter((k) => typeof envIn[k] === "string").sort().map((k) => [k, envIn[k]]);
  const key: unknown[] = [o["home"], o["target"] ?? null, o["ullmBinary"] ?? null, o["otherLoginsRaw"] === true, env];
  // Since 2026-10-21 (§2.10), only when a value has some: a key with none
  // is spelled as before, so a launch with no project MCP config adopts a
  // proxy that predates the field.
  const mcp = Array.isArray(o["mcpConfigs"]) ? (o["mcpConfigs"] as unknown[]).filter((p): p is string => typeof p === "string").sort() : [];
  if (mcp.length > 0) key.push(mcp);
  return JSON.stringify(key);
}

/** The opt-out (`MANDU_OTHER_AGENT_LOGINS=raw`, config `other-agent-logins`):
 *  another agent's login file is registered (its values masked in what
 *  reaches the model, known to the egress gate) but left readable, like the
 *  agent's own key file, for a user who runs one agent inside another. Any
 *  other value is the default (a placeholder copy); `warn` names a value
 *  that is neither. Pure. */
export function otherAgentLoginsRaw(env: Env, warn?: (msg: string) => void): boolean {
  const v = (env["MANDU_OTHER_AGENT_LOGINS"] ?? "").trim().toLowerCase();
  if (v === "raw") return true;
  if (v !== "" && v !== "twin") warn?.(`mandu: MANDU_OTHER_AGENT_LOGINS=${env["MANDU_OTHER_AGENT_LOGINS"]} is not \`raw\` or \`twin\`; other agents' logins get a placeholder copy`);
  return false;
}

/** Is Goose's keyring off for this env? Pure but for the config read. */
export function gooseKeyringDisabled(env: Env, readConfig?: (path: string) => string | null): boolean {
  if (env["GOOSE_DISABLE_KEYRING"] !== undefined) return true; // Goose: env::var(..).is_ok()
  const text = readConfig?.(join(gooseConfigDir(env), "config.yaml")) ?? null;
  if (text === null) return false;
  const v = gooseConfigScalars(text)["GOOSE_DISABLE_KEYRING"];
  return v !== undefined && /^(true|1)$/i.test(v.trim());
}

/** One Goose key variable's login: the variable, then Goose's secret
 *  store (the file, then the keyring when on). Existence checks only. */
function gooseKeyLogin(keyVar: GooseKeyVar | null, deps: LoginProbeDeps, genv: Env): Omit<GooseSubagentLogin, "provider" | "keyVar"> {
  // A provider that takes no key (ollama) has no login to find.
  if (keyVar === null) return { state: "found", via: "a provider that takes no key", howTo: GOOSE_LOGIN_HOWTO };
  const howTo = gooseLoginHowTo(keyVar);
  if (nonEmpty(deps.env[keyVar])) return { state: "found", via: keyVar, howTo };
  const file = gooseSecretsFile(genv);
  // The keyring, when on, is read first; the file is the fallback either
  // way, so an existing file is a login Goose can read under Mandu (which
  // keys it holds is not read: existence only).
  if (deps.fileExists(file)) return { state: "found", via: file, howTo };
  if (gooseKeyringDisabled(genv, deps.readGooseConfig)) return { state: "missing", howTo };
  if (deps.platform === "win32") return { state: "unknown", keyring: true, howTo };
  const item = deps.keyringItem?.(GOOSE_KEYRING_ATTRS) ?? null;
  // macOS: the login Keychain, which the Seatbelt profile leaves reachable,
  // so a key there is a login `mandu goose` keeps working (no `keyring`).
  if (item === true) {
    return deps.platform === "darwin"
      ? { state: "found", via: GOOSE_KEYCHAIN_VIA, howTo }
      : { state: "found", via: "the system keyring", keyring: true, howTo };
  }
  if (item === false) return { state: "missing", howTo };
  return { state: "unknown", keyring: true, howTo };
}

/** Probe one agent's login. Existence checks only. */
export function probeAgentLogin(agent: LoginAgent, deps: LoginProbeDeps): LoginStatus {
  const { env, home, fileExists } = deps;
  if (agent === "goose") {
    const genv = { ...env, HOME: env["HOME"] || home };
    const vars = gooseKeyVars(deps.gooseArgv, genv, deps.readGooseConfig);
    // The keyring item is one JSON object of every secret Goose keeps, so
    // the store's answer is the same for the session and the subagents:
    // asked once.
    let asked: boolean | null | undefined;
    const ask = deps.keyringItem;
    const once: LoginProbeDeps = ask === undefined ? deps : { ...deps, keyringItem: (a) => (asked === undefined ? (asked = ask(a)) : asked) };
    const main: LoginStatus = { agent, ...gooseKeyLogin(vars.main, once, genv) };
    if (vars.sub === vars.main) return main;
    return { ...main, subagent: { provider: vars.subProvider, keyVar: vars.sub, ...gooseKeyLogin(vars.sub, once, genv) } };
  }
  if (agent === "claude") {
    const howTo = CLAUDE_LOGIN_HOWTO;
    for (const k of CLAUDE_ENV) if (nonEmpty(env[k])) return { agent, state: "found", via: k, howTo };
    for (const k of CLAUDE_PROVIDER_SWITCHES) {
      const v = env[k];
      if (nonEmpty(v) && v !== "0" && v!.toLowerCase() !== "false") return { agent, state: "found", via: k, howTo };
    }
    const configDir = nonEmpty(env["CLAUDE_CONFIG_DIR"]) ? env["CLAUDE_CONFIG_DIR"]! : join(home, ".claude");
    const file = join(configDir, ".credentials.json");
    if (fileExists(file)) return { agent, state: "found", via: file, howTo };
    // macOS: Claude Code stores the subscription login in the Keychain, where
    // a file check cannot see it. Say "cannot tell" rather than "missing".
    if (deps.platform === "darwin") return { agent, state: "unknown", howTo };
    return { agent, state: "missing", howTo };
  }
  const howTo = CODEX_LOGIN_HOWTO;
  for (const k of CODEX_ENV) if (nonEmpty(env[k])) return { agent, state: "found", via: k, howTo };
  const codexHome = nonEmpty(env["CODEX_HOME"]) ? env["CODEX_HOME"]! : join(home, ".codex");
  const file = join(codexHome, "auth.json");
  // Signed in to Codex itself: the model proxy relays it (§4).
  if (fileExists(file)) return { agent, state: "found", via: file, signIn: true, howTo };
  return { agent, state: "missing", howTo };
}

/** The first arguments that ARE the agent's own login / auth commands: a
 *  launch running one of them is already doing what the note would ask. */
const LOGIN_SUBCOMMANDS = new Set(["login", "logout", "/login", "auth", "setup-token"]);

/** Which agent a launch starts, when this module can probe it: the target
 *  must be claude/codex/goose AND argv[0] must really be that binary (the
 *  live oracles run a bash stand-in under `--target claude`). */
export function loginAgentOf(target: string, argv: readonly string[]): LoginAgent | null {
  const base = (argv[0] ?? "").split("/").pop() ?? "";
  if (target === "claude" && base === "claude") return "claude";
  if (target === "codex" && base === "codex") return "codex";
  if (target === "goose" && base === "goose") return "goose";
  return null;
}

/** Does this Goose argv run the agent (`session`, `run`, `review` whose
 *  checks are `goose run` children; not help)? Pure. */
function gooseTalksToModel(argv: readonly string[]): boolean {
  const g = readGooseArgv(argv);
  if (!g || (g.command !== "session" && g.command !== "run" && g.command !== "review")) return false;
  return ![...g.globals, ...g.rest].some((a) => a === "-h" || a === "--help" || a === "-V" || a === "--version");
}

/**
 * The ONE plain-language line a launch prints when no login is found, or
 * null (logged in, cannot tell, not an agent we probe, or the launch IS a
 * login command). Printed before the agent starts; never blocks it.
 */
export function launchLoginNote(target: string, argv: readonly string[], deps: LoginProbeDeps): string | null {
  const agent = loginAgentOf(target, argv);
  if (agent === null) return null;
  if (argv[1] !== undefined && LOGIN_SUBCOMMANDS.has(argv[1])) return null;
  if (agent === "goose" && !gooseTalksToModel(argv)) return null;
  const s = probeAgentLogin(agent, agent === "goose" ? { ...deps, gooseArgv: argv } : deps);
  const ignore = "(Logged in some other way? Ignore this line; mandu only checks the usual places.)";
  if (s.state !== "missing") {
    // The session can log in but its subagents' provider cannot.
    const sub = s.subagent;
    if (sub === undefined || sub.state !== "missing") return null;
    return `mandu: WARNING — no login found for Goose's subagents, which GOOSE_SUBAGENT_PROVIDER puts on ${sub.provider}, ` +
      `so a subagent would stop with "Configuration value not found: ${sub.keyVar}"; to log in, ${sub.howTo}. ${ignore}`;
  }
  const name = agent === "claude" ? "Claude Code" : agent === "codex" ? "Codex" : "Goose";
  const also = s.subagent?.state === "missing"
    ? ` (and ${s.subagent.keyVar} for its subagents, which GOOSE_SUBAGENT_PROVIDER puts on ${s.subagent.provider})`
    : "";
  return `mandu: WARNING — no ${name} login found on this machine; to log in, ${s.howTo}${also}. ${ignore}`;
}

/**
 * The ONE line a `mandu goose` launch prints when the agent cannot reach the
 * session bus (the guard's Unix socket allow-list is on, unix-policy.ts) and
 * Goose would have to read its key from the system keyring: no key variable
 * for the routed provider (ANTHROPIC_API_KEY, or OPENAI_API_KEY on openai),
 * no secrets.yaml, the keyring not turned off. Goose then stops with
 * "Configuration value not found: <that variable>". Null otherwise.
 * Existence checks only; never asks the keyring (the line is the same
 * whether or not it holds a key). Supported-agents.md §5.6.1.
 */
export function gooseKeyringNote(target: string, argv: readonly string[], deps: LoginProbeDeps): string | null {
  if (loginAgentOf(target, argv) !== "goose" || !gooseTalksToModel(argv) || deps.platform !== "linux") return null;
  const s = probeAgentLogin("goose", { ...deps, gooseArgv: argv, keyringItem: undefined });
  const keyVar = gooseKeyVar(argv, { ...deps.env, HOME: deps.env["HOME"] || deps.home }, deps.readGooseConfig);
  const out = "which mandu keeps the agent from reaching (the session bus also runs programs outside mandu's protection)";
  const sub = s.subagent?.keyring === true ? s.subagent : undefined;
  if (s.keyring === true) {
    // The subagents' variable too, when it is a different one also unset.
    const also = sub !== undefined ? ` (and ${sub.keyVar} for its subagents, which GOOSE_SUBAGENT_PROVIDER puts on ${sub.provider})` : "";
    return `mandu: WARNING — Goose would read its key from the system keyring, ${out}, so Goose will stop with ` +
      `"Configuration value not found: ${keyVar}"; to fix it, ${s.howTo}${also} (mandu goose lets Goose read that file).`;
  }
  if (sub === undefined) return null;
  return `mandu: WARNING — Goose's subagents, which GOOSE_SUBAGENT_PROVIDER puts on ${sub.provider}, would read their key ` +
    `from the system keyring, ${out}, so a subagent will stop with "Configuration value not found: ${sub.keyVar}"; ` +
    `to fix it, ${sub.howTo} (mandu goose lets Goose read that file).`;
}

/**
 * The refusal for a `mandu codex` launch that would start a model session
 * Codex could not authenticate, or null (agent-sign-in.md §2.3, §2.6).
 * Through the model proxy (the default) either a key variable or Codex's own
 * `codex login` works, so only "neither" is refused. With the user's own base
 * URL (`ownServer`: MANDU_OPENAI_BASE_URL, declared under models: or not) the
 * provider reads a key variable only (env-compose.ts codexProviderToml: a
 * ChatGPT sign-in never goes to that server), so a missing variable is
 * refused there. Either way Codex would otherwise stop with its own error
 * after Mandu had started everything. Only the real `codex` binary and only
 * a command that runs a model turn (codex-argv.ts codexTalksToModel):
 * `codex login`, `codex mcp`, `--version` and a `--target codex` wrapper are
 * never refused. Never falls back to Codex's built-in provider, which would
 * send the turns around the model proxy (codex-argv.ts). Existence checks
 * only, like the rest of this module.
 */
export function codexKeyRefusal(
  target: string,
  argv: readonly string[],
  deps: LoginProbeDeps,
  opts: { ownServer?: boolean } = {},
): string | null {
  if (loginAgentOf(target, argv) !== "codex" || !codexTalksToModel(argv)) return null;
  const s = probeAgentLogin("codex", deps);
  if (opts.ownServer === true) {
    if (s.state === "found" && s.signIn !== true) return null;
    return "mandu: refusing to start Codex: MANDU_OPENAI_BASE_URL points it at your own model server, which needs " +
      "that server's key in CODEX_API_KEY or OPENAI_API_KEY, and neither is set" +
      (s.signIn === true ? ` (your \`codex login\` sign-in, ${s.via}, is never sent to another server)` : "") +
      ". Set the key and launch again. Without it Codex would stop with \"Missing environment variable: OPENAI_API_KEY\".";
  }
  if (s.state === "found") return null;
  return "mandu: refusing to start Codex: it has no sign-in and no OpenAI API key, so it could not reach the model. " +
    `To fix it, ${s.howTo}, then launch again.`;
}

/** The real-host deps: process env, the real HOME, existsSync, Goose's
 *  config.yaml read. No keyring call (`realGooseKeyringItem` is doctor's). */
export function realLoginProbeDeps(env: Env): LoginProbeDeps {
  return {
    env,
    home: env["HOME"] || homedir(),
    fileExists: existsSync,
    platform: process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux",
    readGooseConfig: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
  };
}

/** The `dbus-send` argv that asks the Secret Service which items carry
 *  `attrs`: SearchItems answers two lists of object paths (unlocked,
 *  locked) and never a secret, and it unlocks nothing, so no prompt. Pure. */
export function keyringSearchArgv(attrs: Readonly<Record<string, string>>): string[] {
  const kv = Object.entries(attrs).flatMap(([k, v]) => [k, v]);
  return [
    "dbus-send", "--session", "--print-reply", "--reply-timeout=3000", "--dest=org.freedesktop.secrets",
    "/org/freedesktop/secrets", "org.freedesktop.Secret.Service.SearchItems", `dict:string:string:${kv.join(",")}`,
  ];
}

/** Read `dbus-send`'s answer to `keyringSearchArgv`: true when either list
 *  names an item; false when it names none, or no Secret Service is on the
 *  bus (then no keyring item can exist); null when the bus could not be
 *  asked. Pure. */
export function readKeyringSearch(r: { status: number | null; stdout: string; stderr: string }): boolean | null {
  if (r.status === 0) return /object path "\/[^"]+"/.test(r.stdout);
  if (/ServiceUnknown|NameHasNoOwner|not provided by any \.service files/.test(r.stderr)) return false;
  return null;
}

/** The macOS question: `security find-generic-password` for the item
 *  Goose's keyring crate writes (service `goose`, account `secrets`), with
 *  NEITHER `-w` (print the password) NOR `-g` (print it to stderr): the
 *  answer is the item's attributes only, and an attribute lookup asks the
 *  Keychain no access prompt. By absolute path (a PATH entry cannot stand
 *  in for it). Pure. */
export function keychainSearchArgv(attrs: Readonly<Record<string, string>>): string[] {
  return ["/usr/bin/security", "find-generic-password", "-s", attrs["service"] ?? "", "-a", attrs["username"] ?? ""];
}

/** Read `security`'s answer to `keychainSearchArgv`: true when it found the
 *  item (exit 0), false when the Keychain has none (exit 44,
 *  errSecItemNotFound), null otherwise (no Keychain to search, a locked
 *  or unreadable one, a timeout). Its output is never kept. Pure. */
export function readKeychainSearch(r: { status: number | null; stderr: string }): boolean | null {
  if (r.status === 0) return true;
  if (r.status === 44 || /could not be found in the keychain/i.test(r.stderr)) return false;
  return null;
}

/** How the real probe runs a command (injected by the unit tests). */
export type KeyringCommandRunner = (
  cmd: string,
  args: readonly string[],
  env: Record<string, string>,
) => { status: number | null; stdout: string; stderr: string; error?: Error };

const spawnRunner: KeyringCommandRunner = (cmd, args, env) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 5_000, stdio: ["ignore", "pipe", "pipe"], env });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", ...(r.error ? { error: r.error } : {}) };
};

/** The real keyring existence probe (`mandu doctor`): on Linux the user's
 *  session bus (the Secret Service's SearchItems), on macOS the login
 *  Keychain (`security find-generic-password` without `-w`). Null where it
 *  cannot ask (another platform, no bus address, the command missing). */
export function realGooseKeyringItem(
  env: Env,
  opts: { platform?: NodeJS.Platform; run?: KeyringCommandRunner } = {},
): (attrs: Readonly<Record<string, string>>) => boolean | null {
  const platform = opts.platform ?? process.platform;
  const run = opts.run ?? spawnRunner;
  return (attrs) => {
    if (platform === "darwin") {
      const [cmd, ...args] = keychainSearchArgv(attrs);
      // HOME picks the user's Keychain search list; nothing else is passed.
      const r = run(cmd!, args, { PATH: "/usr/bin:/bin", ...(nonEmpty(env["HOME"]) ? { HOME: env["HOME"]! } : {}) });
      if (r.error) return null;
      return readKeychainSearch(r);
    }
    if (platform !== "linux" || !nonEmpty(env["DBUS_SESSION_BUS_ADDRESS"])) return null;
    const [cmd, ...args] = keyringSearchArgv(attrs);
    const r = run(cmd!, args, { PATH: env["PATH"] ?? "/usr/bin:/bin", DBUS_SESSION_BUS_ADDRESS: env["DBUS_SESSION_BUS_ADDRESS"]! });
    if (r.error) return null;
    return readKeyringSearch({ status: r.status, stdout: r.stdout, stderr: r.stderr });
  };
}
