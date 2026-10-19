/**
 * claude-route — Claude Code's settings files must not re-point its model
 * traffic around Mandu's model proxy (supported-agents.md §2.1 "Settings
 * files"; agent-sdks.md §4).
 *
 * WHY (measured on Claude Code 2.1.290 against two local stand-in models,
 * 2026-10-07). Mandu routes Claude Code by its environment
 * (env-compose.ts: ANTHROPIC_BASE_URL at the model proxy, the session
 * header, the egress proxy variables). Claude Code applies the `env` block of
 * every settings source OVER its own environment, and re-applies it when a
 * settings file changes mid-session. Each of these sent the turn to the
 * other model, around the proxy:
 *   - `env.ANTHROPIC_BASE_URL` in `~/.claude/settings.json`,
 *     `.claude/settings.json`, `.claude/settings.local.json`, the global
 *     `~/.claude.json`, or a `--settings` file;
 *   - the same written into `.claude/settings.local.json` by the agent's own
 *     Bash DURING the session: the next request (the one carrying that
 *     command's result) went to the new URL;
 *   - `env.CLAUDE_CODE_USE_BEDROCK` (any cloud provider switch) with its base
 *     URL: the prompt went to the "Bedrock" endpoint;
 *   - `env.HTTP_PROXY` / `http_proxy` / `ALL_PROXY` with `NO_PROXY` cleared:
 *     the request to the model proxy itself went through another proxy, raw.
 * A `remote-settings.json` the account is not entitled to was ignored, and
 * `--managed-settings` did not apply `env` at all.
 *
 * THE FIX. Settings sources merge in a fixed order (user < project < local <
 * `--settings` < managed), and Claude Code reads only the LAST `--settings`.
 * Mandu therefore passes its routing variables in that last `--settings`
 * (merged into the run's own inline one, never a second), so every lower
 * source, including a file the agent writes mid-session, is overridden on
 * every re-apply (measured: the mid-session write then stayed on the proxy):
 *   - each routing variable (CLAUDE_ROUTE_ENV_KEYS) with the value the
 *     agent is launched with, or "" where the launch has none (an empty
 *     proxy variable is no proxy);
 *   - each provider switch (CLAUDE_PROVIDER_SWITCHES) off, "0".
 * What the overlay cannot outrank is refused before anything starts
 * (claudeRouteRefusal):
 *   - a managed source (the managed file and its drop-ins, the
 *     server-managed cache, macOS MDM) that sets one of those variables to
 *     another value, named;
 *   - a run's own `--settings` FILE: Claude Code would read it instead of
 *     Mandu's, and Mandu does not copy a settings file onto the command line
 *     (every program the agent runs can read that), so the run is refused
 *     with the way out (pass it inline, or put it in a settings file);
 *   - a cloud provider switch or ANTHROPIC_UNIX_SOCKET in the LAUNCH
 *     environment: Claude Code would talk to Bedrock / Vertex / Foundry /
 *     a socket directly, a provider the model proxy does not read. (A
 *     settings file cannot set ANTHROPIC_UNIX_SOCKET: Claude Code ignores it
 *     there.)
 * A lower source that sets one of the variables gets one launch line naming
 * the file: under Mandu it no longer applies.
 *
 * `apiKeyHelper` and the other credential helpers change the KEY Claude
 * Code sends, never where it sends it: the request still goes to
 * ANTHROPIC_BASE_URL, the proxy, so they are left alone.
 *
 * The SDK route (sdk-route-preload.cjs) applies the same overlay to every
 * `claude` a host program starts, with the launch's values (sdk-route.ts
 * SdkRoute.launchRouting, this module's claudeRouteEnv of the agent's
 * environment), never the child's own; its copy of claudeRouteArgs is held
 * equal to this one by a parity unit test.
 *
 * Pure except readClaudeRouteLayers. Mandu-new (no reference origin).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  claudeArgvSettings, claudeConfigDir, claudeSettingsFiles, mergeSettings, readClaudeSettingsSources,
  type ClaudeSettingsFile, type ClaudeSettingsLocations,
} from "./claude-sandbox.js";

/** The variables Mandu routes Claude Code by, re-imposed with the launch's
 *  value (or "") over every settings source. CLAUDE_CODE_API_BASE_URL is the
 *  fallback base of Claude Code's file uploads; ALL_PROXY / all_proxy are
 *  honored for the model request too (measured). */
export const CLAUDE_ROUTE_ENV_KEYS = [
  "ANTHROPIC_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_API_BASE_URL",
  "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
] as const;

/** The cloud providers Claude Code talks to directly (their own wire and
 *  endpoint), which the model proxy does not read (2.1.290). */
export const CLAUDE_CLOUD_SWITCHES = [
  "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
  "CLAUDE_CODE_USE_ANTHROPIC_AWS", "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD", "CLAUDE_CODE_USE_MANTLE",
] as const;

/** Every provider switch the overlay pins: the cloud ones off, and the
 *  gateway login (which sends to ANTHROPIC_BASE_URL, the proxy) as launched. */
export const CLAUDE_PROVIDER_SWITCHES = [...CLAUDE_CLOUD_SWITCHES, "CLAUDE_CODE_USE_GATEWAY"] as const;

const ROUTE_KEYS: ReadonlySet<string> = new Set<string>([...CLAUDE_ROUTE_ENV_KEYS, ...CLAUDE_PROVIDER_SWITCHES]);

/** A switch value as Claude Code reads it (2.1.290: "1", "true", "yes",
 *  "on", any case, trimmed). */
export function claudeSwitchOn(v: string | undefined): boolean {
  return v !== undefined && ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

/** The `env` the overlay re-imposes, from the environment the agent is
 *  launched with. Pure. */
export function claudeRouteEnv(agentEnv: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of CLAUDE_ROUTE_ENV_KEYS) out[k] = agentEnv[k] ?? "";
  for (const k of CLAUDE_CLOUD_SWITCHES) out[k] = "0";
  out["CLAUDE_CODE_USE_GATEWAY"] = claudeSwitchOn(agentEnv["CLAUDE_CODE_USE_GATEWAY"]) ? agentEnv["CLAUDE_CODE_USE_GATEWAY"]! : "0";
  return out;
}

/** Why the LAUNCH environment cannot be routed, or null: a cloud provider
 *  switch, or a Unix socket in place of the base URL. Pure. */
export function claudeEnvRefusal(agentEnv: Record<string, string | undefined>): string | null {
  const on = CLAUDE_CLOUD_SWITCHES.filter((k) => claudeSwitchOn(agentEnv[k]));
  if (on.length > 0) {
    return (
      `mandu: refusing to launch Claude Code with ${on.join(", ")} set: Claude Code would send its model traffic to that cloud ` +
      "provider directly, around Mandu's model proxy, so tool results would reach the model unmasked. Mandu routes the Anthropic " +
      `API only; unset ${on.length === 1 ? "it" : "them"} to run under Mandu.`
    );
  }
  if ((agentEnv["ANTHROPIC_UNIX_SOCKET"] ?? "").trim() !== "") {
    return (
      "mandu: refusing to launch Claude Code with ANTHROPIC_UNIX_SOCKET set: Claude Code would send its model traffic to that " +
      "socket, around Mandu's model proxy, so tool results would reach the model unmasked. Unset it to run under Mandu."
    );
  }
  return null;
}

/** The overlay the launch's last `--settings` carries. */
export function claudeRouteOverlay(agentEnv: Record<string, string | undefined>): { env: Record<string, string> } {
  return { env: claudeRouteEnv(agentEnv) };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A `--settings` value Claude Code reads as inline JSON (it looks like an
 *  object), parsed, or null when it is not one. */
function inlineSettings(value: string): Record<string, unknown> | null {
  const t = value.trim();
  if (!(t.startsWith("{") && t.endsWith("}"))) return null;
  try {
    const doc = JSON.parse(t) as unknown;
    return isRecord(doc) ? doc : null;
  } catch {
    return null;
  }
}

/** The settings with the overlay's `env` merged in, the overlay winning. */
function withOverlay(doc: Record<string, unknown>, overlay: { env: Record<string, string> }): Record<string, unknown> {
  return mergeSettings(doc, overlay) as Record<string, unknown>;
}

/**
 * The command line with the overlay in the `--settings` Claude Code reads:
 * merged into the run's own LAST `--settings` when it is inline JSON (in
 * `argv`, either spelling), else into the last inline `--settings` of
 * `prefix` (the launch's own: the TUI pin, the sandbox overlay), else a new
 * one at the head of `prefix`. A run's own `--settings` that is a file (or
 * not a JSON object) is refused: Claude Code would read it instead of
 * Mandu's. Copies; the inputs are not changed. Pure.
 */
export function claudeRouteArgs(
  argv: readonly string[],
  prefix: readonly string[],
  overlay: { env: Record<string, string> },
): { argv: string[]; prefix: string[] } | { refusal: string } {
  const outArgv = [...argv];
  const outPrefix = [...prefix];
  const own = claudeArgvSettings(argv);
  if (own !== null) {
    const doc = inlineSettings(own.value);
    if (doc === null) {
      return {
        refusal:
          `mandu: refusing to launch Claude Code with --settings ${own.value}: Claude Code reads only the last --settings, so ` +
          "it would read that one instead of Mandu's, whose routing keeps Claude Code's model traffic on Mandu's model proxy " +
          "(a settings file can point it elsewhere). Mandu does not copy a settings file onto the command line, where every " +
          "program the AI runs can read it. Pass those settings inline (--settings '{…}') or put them in " +
          ".claude/settings.local.json.",
      };
    }
    const merged = JSON.stringify(withOverlay(doc, overlay));
    if (own.form === "split") outArgv[own.index + 1] = merged;
    else outArgv[own.index] = `--settings=${merged}`;
    return { argv: outArgv, prefix: outPrefix };
  }
  for (let i = outPrefix.length - 2; i >= 0; i--) {
    if (outPrefix[i] !== "--settings") continue;
    const doc = inlineSettings(outPrefix[i + 1]!);
    if (doc !== null) {
      outPrefix[i + 1] = JSON.stringify(withOverlay(doc, overlay));
      return { argv: outArgv, prefix: outPrefix };
    }
    break;
  }
  outPrefix.unshift("--settings", JSON.stringify(overlay));
  return { argv: outArgv, prefix: outPrefix };
}

/** One settings source Claude Code applies `env` from, as read. */
export interface ClaudeRouteLayer {
  path: string;
  scope: ClaudeSettingsFile["scope"] | "global";
  text: string | null;
  unreadable?: boolean;
}

/** One routing variable a source sets to a value other than the launch's. */
export interface ClaudeRouteConflict {
  path: string;
  scope: ClaudeRouteLayer["scope"];
  key: string;
}

/** The routing variables each source's `env` sets to a value other than
 *  the overlay's (names compared as Claude Code applies them: exact, so
 *  `http_proxy` and `HTTP_PROXY` are two). A source that does not parse is
 *  skipped (Claude Code skips it too). Pure. */
export function claudeRouteConflicts(layers: readonly ClaudeRouteLayer[], overlayEnv: Record<string, string>): ClaudeRouteConflict[] {
  const out: ClaudeRouteConflict[] = [];
  for (const l of layers) {
    if (l.text === null || l.text.trim() === "") continue;
    let doc: unknown;
    try { doc = JSON.parse(l.text.startsWith("﻿") ? l.text.slice(1) : l.text); } catch { continue; }
    if (!isRecord(doc) || !isRecord(doc["env"])) continue;
    for (const [k, v] of Object.entries(doc["env"])) {
      if (!ROUTE_KEYS.has(k)) continue;
      if (String(v) === overlayEnv[k]) continue;
      // A switch set off (or empty) in a file changes nothing.
      if ((CLAUDE_PROVIDER_SWITCHES as readonly string[]).includes(k) && !claudeSwitchOn(String(v)) && !claudeSwitchOn(overlayEnv[k])) continue;
      out.push({ path: l.path, scope: l.scope, key: k });
    }
  }
  return out;
}

/** The `--managed-settings` values of an argv that are inline JSON setting
 *  a routing variable (Claude Code 2.1.290 does not apply their `env`; a
 *  later one might, and it would outrank Mandu's `--settings`). Pure. */
function managedArgConflicts(argv: readonly string[], overlayEnv: Record<string, string>): string[] {
  const out: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    let v: string | undefined;
    if (a === "--managed-settings" && i + 1 < argv.length) v = argv[++i];
    else if (a.startsWith("--managed-settings=")) v = a.slice("--managed-settings=".length);
    if (v === undefined) continue;
    const doc = inlineSettings(v);
    if (doc === null) continue;
    for (const c of claudeRouteConflicts([{ path: "--managed-settings", scope: "managed", text: JSON.stringify(doc) }], overlayEnv)) out.push(c.key);
  }
  return [...new Set(out)];
}

/**
 * The launch-time verdict for a Claude Code session: a refusal (the launch
 * environment, a managed source or a `--managed-settings` the overlay
 * cannot outrank, a run's own `--settings` file), or the notes naming each
 * lower source whose routing no longer applies under Mandu. `argv` is the
 * agent's command line (argv[0] first); `layers` every source Claude Code
 * applies `env` from. Pure.
 */
export function claudeRouteRefusal(
  argv: readonly string[],
  agentEnv: Record<string, string | undefined>,
  layers: readonly ClaudeRouteLayer[],
): { refusal: string } | { notes: string[] } {
  const envRefusal = claudeEnvRefusal(agentEnv);
  if (envRefusal !== null) return { refusal: envRefusal };
  const overlay = claudeRouteOverlay(agentEnv);
  const args = claudeRouteArgs(argv, [], overlay);
  if ("refusal" in args) return args;
  const managedArg = managedArgConflicts(argv, overlay.env);
  if (managedArg.length > 0) {
    return {
      refusal:
        `mandu: refusing to launch Claude Code: this run's --managed-settings sets ${managedArg.map((k) => `env.${k}`).join(", ")}, ` +
        "which would outrank Mandu's routing and send Claude Code's model traffic around Mandu's model proxy. Remove it to run under Mandu.",
    };
  }
  const conflicts = claudeRouteConflicts(layers, overlay.env);
  const managed = conflicts.filter((c) => c.scope === "managed");
  if (managed.length > 0) {
    const files = [...new Set(managed.map((c) => c.path))];
    return {
      refusal:
        `mandu: refusing to launch Claude Code: managed settings (${files.join(", ")}) set ` +
        `${[...new Set(managed.map((c) => `env.${c.key}`))].join(", ")}, which outrank Mandu's routing and would send Claude Code's ` +
        "model traffic around Mandu's model proxy, so tool results would reach the model unmasked. Ask the administrator, or run " +
        "Claude Code without Mandu on this machine.",
    };
  }
  const unread = layers.filter((l) => l.scope === "managed" && l.unreadable === true).map((l) => l.path);
  if (unread.length > 0) {
    return {
      refusal:
        `mandu: refusing to launch Claude Code: managed settings Mandu cannot read (${unread.join(", ")}) outrank Mandu's routing ` +
        "and could send Claude Code's model traffic around Mandu's model proxy.",
    };
  }
  const notes: string[] = [];
  const byFile = new Map<string, string[]>();
  for (const c of conflicts) byFile.set(c.path, [...(byFile.get(c.path) ?? []), `env.${c.key}`]);
  for (const [path, keys] of byFile) {
    notes.push(
      `mandu: ${path} sets ${[...new Set(keys)].join(", ")}; under Mandu ${keys.length === 1 ? "it does" : "they do"} not apply: ` +
      "Mandu's own --settings keeps Claude Code's model traffic on Mandu's model proxy for this session. To use your own model " +
      "endpoint, set ANTHROPIC_BASE_URL in the environment and declare it under models: in policy.yaml.",
    );
  }
  return { notes };
}

/** Every source Claude Code applies `env` from for a launch in `cwd`: the
 *  global config (`.claude.json` in CLAUDE_CONFIG_DIR, else in the home),
 *  then the settings sources claude-sandbox.ts reads, the run's own
 *  `--settings` file excluded (claudeRouteArgs refuses it). */
export function readClaudeRouteLayers(opts: {
  env: Record<string, string | undefined>;
  home: string;
  cwd: string;
  platform: NodeJS.Platform;
  locations: ClaudeSettingsLocations;
  readFile?: (p: string) => string | null;
  readPlistJson?: (p: string) => string | null;
  exists?: (p: string) => boolean;
}): ClaudeRouteLayer[] {
  const readFile = opts.readFile ?? ((p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } });
  const globalPath = opts.env["CLAUDE_CONFIG_DIR"]?.trim()
    ? join(claudeConfigDir(opts.env, opts.home), ".claude.json")
    : join(opts.home, ".claude.json");
  const files = readClaudeSettingsSources(claudeSettingsFiles(opts.home, opts.cwd, opts.platform, opts.locations), {
    readFile,
    readPlistJson: opts.readPlistJson ?? (() => null),
    exists: opts.exists ?? existsSync,
  });
  return [
    { path: globalPath, scope: "global" as const, text: readFile(globalPath) },
    ...files.map((f) => ({ path: f.path, scope: f.scope, text: f.text, ...(f.unreadable === true ? { unreadable: true } : {}) })),
  ];
}
