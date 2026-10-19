/**
 * claude-permission-rule — THE one copy of the rule that decides whether a
 * Claude Code command line gets `--permission-mode default` under Mandu
 * (supported-agents.md §2, "Claude Code's permission mode under Mandu";
 * decided 2026-10-09, extended 2026-10-18).
 *
 * Three places apply it, all through this file:
 *   - the launch itself, for `mandu claude` (claude-permission-mode.ts, a
 *     typed wrapper that feeds it the settings files the launch read);
 *   - the SDK route's preload, for every `claude` a Node or Python host
 *     starts (sdk-route-preload.cjs claudeModeArgs);
 *   - the PATH shim `<scope run dir>/sdk-shims/claude`, for a `claude` found
 *     by name anywhere in a claude or shell session: one a shell started
 *     (`mandu -- bash`, then `claude`), a script, the agent's own Bash tool
 *     (sdk-route.ts claudeShimScript; the preload's `--claude`
 *     entry).
 *
 * THE RULE. `--permission-mode default` goes ahead of the arguments of a
 * Claude Code command line that starts a session, unless the line or a
 * settings source Claude Code reads for it already chose a mode:
 *   - `--permission-mode <any>` (either spelling);
 *   - `--dangerously-skip-permissions` (it starts in bypassPermissions);
 *   - `--inherit-permission-mode <any>` (either spelling): the mode a parent
 *     session hands a child it starts, "used only when nothing else
 *     configures one" (Claude Code 2.1.302 help), so our flag would
 *     override the parent's mode;
 *   - `permissions.defaultMode` (a non-empty string) in the line's last
 *     `--settings` or in any `--managed-settings`;
 *   - one in a settings scope Claude Code reads for it (`scopeChoice`: the
 *     managed sources always; the user, project and local files unless
 *     `--setting-sources` leaves them out, none under `--restricted`).
 *
 * Not a choice: `--allow-dangerously-skip-permissions`. Measured on
 * 2.1.290 – 2.1.295 (alone it started in `auto`) and read in 2.1.302's
 * bundle (2026-10-18): the start-mode resolver takes the mode from
 * `--permission-mode`, `--inherit-permission-mode`,
 * `--dangerously-skip-permissions`, an agent's frontmatter and the settings'
 * `defaultMode`; `--allow-dangerously-skip-permissions` only makes
 * bypassPermissions selectable later (Shift+Tab) and lets a settings
 * `defaultMode: "bypassPermissions"` take effect, which the settings check
 * already counts. So with it the flag is still added, and bypass stays one
 * Shift+Tab away, as without Mandu.
 *
 * Only a session: not `--version` / `--help` before a `--`, nor a
 * subcommand that runs none or takes no root permission flag (claude-
 * sandbox.ts CLAUDE_NON_SESSION, which the routing uses, plus `agents`,
 * `remote-control` / `rc` and `daemon`: `claude daemon` is recognised only
 * as the first argument after the skip-permissions flags, so a flag ahead
 * of it would turn it into a prompt). The unit test holds this set a
 * superset of CLAUDE_NON_SESSION.
 *
 * Plain CommonJS that requires nothing, not even Node's builtins (the
 * launcher's ESM bundle cannot serve a CommonJS `require`; the one function
 * that touches the filesystem takes `fs` and `path` from its caller): the
 * preload loads it inside the user's program and the shim, from the source
 * tree and from the installed bundle alike (bundle-manifest.json `assets`,
 * next to the preload), and the launcher imports it
 * (claude-permission-rule.d.cts).
 *
 * Mandu-new (no reference origin).
 */
"use strict";

/** What the rule adds: Claude Code's default (manual-approval) mode. */
const DEFAULT_PERMISSION_ARGS = Object.freeze(["--permission-mode", "default"]);

/** The file scopes `--setting-sources` selects among. */
const FILE_SCOPES = Object.freeze(["user", "project", "local"]);

/** First arguments that start no session, or take no root permission flag. */
const NO_MODE_SUBCOMMANDS = new Set([
  // claude-sandbox.ts CLAUDE_NON_SESSION (a superset is held by the unit test)
  "mcp", "config", "doctor", "update", "upgrade", "install", "migrate-installer", "setup-token", "plugin", "plugins", "sandbox", "auth",
  "auto-mode", "import", "project", "ultrareview", "gateway",
  // 2.1.302's other root commands
  "agents", "remote-control", "rc", "daemon",
]);

/** The flags whose presence (with its value) is a mode chosen on the line. */
const MODE_VALUE_FLAGS = ["--permission-mode", "--inherit-permission-mode"];

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Whether a command line (arguments WITHOUT argv[0]) takes the flag: it
 *  starts a session and its first argument is no subcommand that does not. */
function takesPermissionMode(args) {
  let i = 0;
  // `claude [--dangerously-skip-permissions|--allow-…] daemon` (2.1.302).
  while (args[i] === "--dangerously-skip-permissions" || args[i] === "--allow-dangerously-skip-permissions") i++;
  if (args[i] === "daemon") return false;
  if (args[0] !== undefined && NO_MODE_SUBCOMMANDS.has(String(args[0]))) return false;
  for (const a of args) {
    if (a === "--") break;
    if (a === "--version" || a === "-v" || a === "--help" || a === "-h") return false;
  }
  return true;
}

/** The flag on a command line (arguments WITHOUT argv[0]) that chose the
 *  permission mode, as written, or null. The whole line is scanned, past a
 *  `--` too: a false match only leaves the mode as Claude Code picks it. */
function argvModeFlag(args) {
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === "--dangerously-skip-permissions") return a;
    for (const f of MODE_VALUE_FLAGS) {
      if (a === f) return args[i + 1] !== undefined ? `${a} ${args[i + 1]}` : a;
      if (a.startsWith(`${f}=`)) return a;
    }
  }
  return null;
}

/** The file scopes Claude Code reads for a command line (arguments WITHOUT
 *  argv[0]): all three unless `--setting-sources` (its last value,
 *  comma-separated) names some, none under `--restricted`. Managed sources
 *  and `--settings` are always read. */
function argvFileScopes(args) {
  let list = null;
  let restricted = false;
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === "--restricted") restricted = true;
    else if (a === "--setting-sources" && i + 1 < args.length) list = String(args[++i]);
    else if (a.startsWith("--setting-sources=")) list = a.slice("--setting-sources=".length);
  }
  if (restricted) return [];
  if (list === null) return [...FILE_SCOPES];
  const named = new Set(list.split(",").map((s) => s.trim()));
  return FILE_SCOPES.filter((s) => named.has(s));
}

/** A settings document's `permissions.defaultMode`, when it sets one (a
 *  non-empty string; a mode name Claude Code does not know still counts, so
 *  a newer mode is never overridden). */
function settingsDefaultMode(doc) {
  if (!isPlainObject(doc) || !isPlainObject(doc.permissions)) return null;
  const m = doc.permissions.defaultMode;
  return typeof m === "string" && m.trim() !== "" ? m : null;
}

/** The values a command line (arguments WITHOUT argv[0]) gives an option,
 *  either spelling. */
function optionValues(args, name) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === name && i + 1 < args.length) out.push(String(args[++i]));
    else if (a.startsWith(`${name}=`)) out.push(a.slice(name.length + 1));
  }
  return out;
}

/** The mode the command line itself chose (a flag, the last `--settings`,
 *  a `--managed-settings`), described, or null. `parseValue` reads one
 *  `--settings` value (inline JSON or a file) into a document, or null. */
function argvModeChoice(args, parseValue) {
  const flag = argvModeFlag(args);
  if (flag !== null) return flag;
  const settings = optionValues(args, "--settings");
  const last = settings[settings.length - 1];
  if (last !== undefined && settingsDefaultMode(parseValue(last)) !== null) return "--settings (permissions.defaultMode)";
  for (const v of optionValues(args, "--managed-settings")) {
    if (settingsDefaultMode(parseValue(v)) !== null) return "--managed-settings (permissions.defaultMode)";
  }
  return null;
}

/**
 * THE RULE: `{inject: true}`, or `{inject: false, reason}`. `args` is the
 * command line WITHOUT argv[0]; `parseValue(value)` reads a `--settings` /
 * `--managed-settings` value; `scopeChoice(fileScopes)` answers for the
 * settings scopes Claude Code reads for it (the managed ones and
 * `fileScopes`): why one sets a mode (or why it cannot be known), or null.
 * Pure over the two readers.
 */
function permissionModeDecision(args, parseValue, scopeChoice) {
  if (!takesPermissionMode(args)) return { inject: false, reason: "no session" };
  const own = argvModeChoice(args, parseValue);
  if (own !== null) return { inject: false, reason: own };
  const scoped = scopeChoice(argvFileScopes(args));
  if (scoped !== null) return { inject: false, reason: scoped };
  return { inject: true };
}

/** `args` with the rule's flag ahead when the decision injects; the same
 *  array otherwise. */
function withPermissionMode(args, decision) {
  return decision.inject ? [...DEFAULT_PERMISSION_ARGS, ...args] : args;
}

/** The first executable `name` on `pathValue` outside `skipDir` (and not a
 *  link into it), or null: what a PATH shim in `skipDir` runs, and what the
 *  launch starts by path when it puts that shim ahead of the agent. `fs`
 *  and `path` are Node's (`node:fs`, `node:path`), passed in. */
function realExecutable(name, pathValue, skipDir, fs, path) {
  const real = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
  const skip = real(skipDir);
  for (const dir of String(pathValue || "").split(path.delimiter)) {
    if (dir === "" || real(dir) === skip) continue;
    const candidate = path.join(dir, name);
    try {
      if (!fs.statSync(candidate).isFile()) continue;
      fs.accessSync(candidate, fs.constants.X_OK);
    } catch { continue; }
    if (path.dirname(real(candidate)) === skip) continue;
    return candidate;
  }
  return null;
}

module.exports = {
  DEFAULT_PERMISSION_ARGS,
  FILE_SCOPES,
  NO_MODE_SUBCOMMANDS,
  takesPermissionMode,
  argvModeFlag,
  argvFileScopes,
  settingsDefaultMode,
  optionValues,
  argvModeChoice,
  permissionModeDecision,
  withPermissionMode,
  realExecutable,
};
